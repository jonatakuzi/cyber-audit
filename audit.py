#!/usr/bin/env python3
"""CyberAudit - A Python security audit toolkit"""
import argparse, hashlib, math, re, secrets, string, sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

RED="\033[91m";YELLOW="\033[93m";GREEN="\033[92m";CYAN="\033[96m";BOLD="\033[1m";RESET="\033[0m"
def color(t,c): return f"{c}{t}{RESET}"

COMMON_PASSWORDS={"password","password1","123456","12345678","1234","qwerty","abc123","monkey","letmein","trustno1","dragon","baseball","iloveyou","master","sunshine","passw0rd","shadow","123123","654321","superman","michael","football","password2","admin","welcome","login","hello","charlie","password123","admin123","root","toor","pass","test","guest","111111","000000","1q2w3e4r"}

def calc_entropy(pw):
    pool=0
    if re.search(r'[a-z]',pw): pool+=26
    if re.search(r'[A-Z]',pw): pool+=26
    if re.search(r'\d',pw): pool+=10
    if re.search(r'[^a-zA-Z0-9]',pw): pool+=32
    return len(pw)*math.log2(pool) if pool else 0

def check_password(pw):
    issues,score=[],100
    if len(pw)<8: issues.append("Too short (min 8 chars)");score-=30
    elif len(pw)<12: issues.append("Short - 12+ chars recommended");score-=10
    if not re.search(r'[A-Z]',pw): issues.append("No uppercase");score-=10
    if not re.search(r'[a-z]',pw): issues.append("No lowercase");score-=10
    if not re.search(r'\d',pw): issues.append("No digits");score-=10
    if not re.search(r'[^a-zA-Z0-9]',pw): issues.append("No special chars");score-=10
    if pw.lower() in COMMON_PASSWORDS: issues.append("Common password");score-=40
    if re.search(r'(.)\1{2,}',pw): issues.append("Repeated chars");score-=10
    if any(w in pw.lower() for w in ["qwerty","asdf","zxcv","1234","abcd"]): issues.append("Keyboard walk");score-=10
    score=max(0,min(100,score))
    rating,col=("Strong",GREEN) if score>=80 else ("Moderate",YELLOW) if score>=50 else ("Weak",RED)
    return {"score":score,"rating":rating,"color":col,"entropy":calc_entropy(pw),"issues":issues}

def cmd_password(args):
    r=check_password(args.password)
    print(f"\nPassword Analysis\n  Length: {len(args.password)} chars | Entropy: {r['entropy']:.1f} bits")
    print(f"  Score: {r['score']}/100 | Rating: {r['rating']}")
    for i in r["issues"]: print(f"  x {i}")
    print()

def cmd_generate(args):
    alpha=string.ascii_letters+string.digits+"!@#$%^&*()-_=+[]{}|;:,.<>?"
    while True:
        pw=''.join(secrets.choice(alpha) for _ in range(args.length))
        if check_password(pw)["score"]>=80: break
    print(f"\nGenerated: {pw}\n  Entropy: {calc_entropy(pw):.1f} bits\n")

PAT={"failed":re.compile(r'Failed password for (\S+) from ([\d.]+)',re.I),"invalid":re.compile(r'Invalid user (\S+) from ([\d.]+)',re.I),"accepted":re.compile(r'Accepted (?:password|publickey) for (\S+) from ([\d.]+)',re.I),"http":re.compile(r'([\d.]+) .+ "(GET|POST|PUT|DELETE) ([^ ]+) HTTP[^"]+" (4\d{2}|5\d{2})'),"sudo":re.compile(r'sudo.+authentication failure.*user=(\S+)',re.I)}

def cmd_logs(args):
    path=Path(args.file)
    if not path.exists(): print(f"Error: {path} not found");sys.exit(1)
    fi,fu,acc,he,sf=defaultdict(int),defaultdict(int),[],defaultdict(int),[]
    n=0
    with open(path,errors="replace") as f:
        for line in f:
            n+=1
            for k in ["failed","invalid"]:
                m=PAT[k].search(line)
                if m: fi[m.group(2)]+=1;fu[m.group(1)]+=1;break
            else:
                for k,lst in [("accepted",acc),("sudo",sf)]:
                    m=PAT[k].search(line)
                    if m: lst.append((m.group(1),m.group(2)) if k=="accepted" else m.group(1))
                m=PAT["http"].search(line)
                if m: he[m.group(1)]+=1
    bf={ip:c for ip,c in fi.items() if c>=10}
    print(f"\nLog Report: {path.name} ({n:,} lines)")
    if bf:
        print(f"  WARNING: {len(bf)} brute-force IPs")
        for ip,c in sorted(bf.items(),key=lambda x:-x[1])[:10]: print(f"    {ip} - {c} attempts")
    else: print("  OK: No brute-force detected")
    if fu: print("\n  Top targets: "+", ".join(f"{u}({c})" for u,c in sorted(fu.items(),key=lambda x:-x[1])[:5]))
    if acc: print(f"\n  Logins: {len(acc)} successful")
    if he: print("\n  HTTP errors from: "+", ".join(sorted(he,key=lambda x:-he[x])[:3]))
    if sf: print(f"\n  WARNING: sudo failures by {set(sf)}")
    print()

def hash_file(p,algo="sha256"):
    h=hashlib.new(algo)
    with open(p,"rb") as f:
        for chunk in iter(lambda:f.read(65536),b""): h.update(chunk)
    return h.hexdigest()

def cmd_hash(args):
    path=Path(args.file)
    if not path.exists(): print(f"Error: {path}");sys.exit(1)
    d=hash_file(path,args.algo)
    print(f"\nFile: {path}\nAlgo: {args.algo.upper()}\nHash: {d}")
    if args.verify: print("MATCH" if d.lower()==args.verify.lower() else "MISMATCH")
    print()

def main():
    p=argparse.ArgumentParser(prog="audit",description="CyberAudit - security toolkit")
    s=p.add_subparsers(dest="command",required=True)
    pw=s.add_parser("password");pw.add_argument("password")
    g=s.add_parser("generate");g.add_argument("--length",type=int,default=16)
    l=s.add_parser("logs");l.add_argument("file")
    h=s.add_parser("hash");h.add_argument("--file",required=True);h.add_argument("--algo",default="sha256",choices=["md5","sha1","sha256","sha512"]);h.add_argument("--verify")
    a=p.parse_args()
    {"password":cmd_password,"generate":cmd_generate,"logs":cmd_logs,"hash":cmd_hash}[a.command](a)

if __name__=="__main__": main()
