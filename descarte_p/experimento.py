#!/usr/bin/env python3
import re
import shlex
import statistics
import subprocess
import time

THRIFT = 9090
REPS = 3  # repeticoes por politica
IPS = {"h1": "10.0.1.1", "h2": "10.0.2.1", "h3": "10.0.3.1"}
MODOS = [(0, "sem mitigacao"), (1, "descarte total"), (2, "descarte probabilistico")]
REGS = ["reg_count", "reg_win", "reg_anom", "reg_first_ts", "reg_detect_ts",
        "reg_passed", "reg_dropped", "bloom1", "bloom2"]
PIDS = {}


def cli(cmd):
    r = subprocess.run(["simple_switch_CLI", "--thrift-port", str(THRIFT)],
                       input=cmd + "\n", text=True, capture_output=True)
    return r.stdout


def pid_host(h):
    out = subprocess.run(["pgrep", "-f", "mininet:%s$" % h],
                         capture_output=True, text=True).stdout.split()
    if not out:
        raise SystemExit("Host %s nao encontrado. O make run esta aberto?" % h)
    return out[0]


def run_bg(h, cmd, arq):
    f = open(arq, "w")
    p = subprocess.Popen(["mnexec", "-a", PIDS[h]] + shlex.split(cmd),
                         stdout=f, stderr=subprocess.STDOUT)
    return p, f


def run_fg(h, cmd, timeout=120):
    r = subprocess.run(["mnexec", "-a", PIDS[h]] + shlex.split(cmd),
                       capture_output=True, text=True, timeout=timeout)
    return r.stdout + r.stderr


def idx(ip):
    # Mesmo indice do P4: 3o octeto do IP (10.0.X.1 -> X)
    return int(ip.split(".")[2])


def ler_reg(nome):
    out = cli("register_read MyIngress.%s" % nome)
    m = re.search(r"=\s*([\d,\s]+)", out)
    if not m:
        return []
    return [int(x) for x in m.group(1).replace(" ", "").split(",") if x != ""]


def iperf_mbps(txt):
    v = re.findall(r"([\d.]+)\s+([KMG])bits/sec", txt)
    if not v:
        return None
    n, u = v[-1]
    return float(n) * {"K": 0.001, "M": 1, "G": 1000}[u]


def ping_stats(txt):
    loss = re.search(r"([\d.]+)% packet loss", txt)
    rtt = re.search(r"= [\d.]+/([\d.]+)/", txt)
    return (float(loss.group(1)) if loss else None,
            float(rtt.group(1)) if rtt else None)


def experimento(modo, nome):
    for r in REGS:
        cli("register_reset MyIngress.%s" % r)
    cli("register_write MyIngress.reg_mode 0 %d" % modo)
    time.sleep(1)

    abertos = []
    for cmd, arq in [("iperf -s -p 5001", "srv_iperf.txt"),
                     ("python3 -m http.server 80 --bind %s" % IPS["h3"], "srv80.txt"),
                     ("python3 -m http.server 443 --bind %s" % IPS["h3"], "srv443.txt")]:
        abertos.append(run_bg("h3", cmd, arq))
    time.sleep(1.5)

    p_ping1, f1 = run_bg("h1", "ping -c 50 -i 0.2 %s" % IPS["h3"], "ping_h1.txt")
    p_iperf, f2 = run_bg("h1", "iperf -c %s -p 5001 -t 12" % IPS["h3"], "iperf_h1.txt")
    time.sleep(3)

    p_ping2, f3 = run_bg("h2", "ping -c 16 -i 0.5 %s" % IPS["h3"], "ping_h2.txt")
    scan = run_fg("h2", "nmap -sS -p 1-1024 -T4 --max-retries 0 -n %s" % IPS["h3"])

    p_ping1.wait()
    p_iperf.wait()
    p_ping2.wait()
    for f in (f1, f2, f3):
        f.close()
    for p, f in abertos:
        p.terminate()
        f.close()

    t1 = open("iperf_h1.txt").read()
    pg1 = ping_stats(open("ping_h1.txt").read())
    pg2 = ping_stats(open("ping_h2.txt").read())
    abertas = len(re.findall(r"^\d+/tcp\s+open", scan, re.M))
    dur = re.search(r"scanned in ([\d.]+) seconds", scan)

    passed = ler_reg("reg_passed")
    dropped = ler_reg("reg_dropped")
    first = ler_reg("reg_first_ts")
    detect = ler_reg("reg_detect_ts")
    i1, i2 = idx(IPS["h1"]), idx(IPS["h2"])
    if not passed or not (passed[i2] or dropped[i2]):
        print("AVISO: indice do H2 (%d) sem atividade" % i2)
        return None

    tdet = None
    if detect[i2] and first[i2] and detect[i2] >= first[i2]:
        tdet = (detect[i2] - first[i2]) / 1000.0

    return {
        "h1_iperf_mbps": iperf_mbps(t1),
        "h1_perda_%": pg1[0],
        "h1_rtt_ms": pg1[1],
        "h2_perda_ping_%": pg2[0],
        "h2_rtt_ms": pg2[1],
        "scan_portas_abertas_vistas": abertas,
        "scan_duracao_s": float(dur.group(1)) if dur else None,
        "h2_pacotes_passaram": passed[i2],
        "h2_pacotes_descartados": dropped[i2],
        "h1_pacotes_passaram": passed[i1],
        "h1_pacotes_descartados": dropped[i1],
        "tempo_deteccao_ms": tdet,
    }


def agrega(runs):
    out = {}
    for c in runs[0]:
        v = [r[c] for r in runs if r[c] is not None]
        if not v:
            out[c] = "None"
        elif len(v) == 1:
            out[c] = "%.2f" % v[0]
        else:
            out[c] = "%.2f +- %.2f" % (statistics.mean(v), statistics.stdev(v))
    return out


def main():
    for h in IPS:
        PIDS[h] = pid_host(h)
    assert len({idx(ip) for ip in IPS.values()}) == len(IPS), "colisao de indices"

    resultados = []
    for modo, nome in MODOS:
        runs = []
        for i in range(REPS):
            print("Rodando: %s (%d/%d) ..." % (nome, i + 1, REPS))
            r = experimento(modo, nome)
            if r:
                runs.append(r)
            time.sleep(2)
        if runs:
            a = agrega(runs)
            a["politica"] = nome
            resultados.append(a)

    if not resultados:
        raise SystemExit("Sem resultados.")
    cols = ["politica"] + [c for c in resultados[0] if c != "politica"]
    for c in cols:
        print("%-28s" % c, " | ".join("%-22s" % r[c] for r in resultados))


main()

