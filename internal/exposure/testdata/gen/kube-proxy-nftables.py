#!/usr/bin/env python3
# Writes the kube-proxy nftables fixtures in `nft -j list ruleset` form, by hand from
# kube-proxy's source (pkg/proxy/nftables/proxier.go: release-1.31, release-1.34, master)
# and the CNI portmap plugin's portmap_nftables.go. Not taken from a live cluster.
#   python3 testdata/gen/kube-proxy-nftables.py 1.31   > testdata/kube-proxy-nftables.json
#   python3 testdata/gen/kube-proxy-nftables.py 1.34   > testdata/kube-proxy-nftables-1.34.json
#   python3 testdata/gen/kube-proxy-nftables.py master > testdata/kube-proxy-nftables-master.json
import json,sys
V=sys.argv[1] if len(sys.argv)>1 else "1.31"
out=[]
def add(kind,obj): out.append({kind:obj})
M={"metainfo":{"version":"1.1.3","release_name":"Commodore Bullmoose #4","json_schema_version":1}}
out.append(M)
T="kube-proxy"
def tcpd(p): return {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":p}}
def daddr(a,op="=="): return {"match":{"op":op,"left":{"payload":{"protocol":"ip","field":"daddr"}},"right":a}}
def saddr(a,op="=="): return {"match":{"op":op,"left":{"payload":{"protocol":"ip","field":"saddr"}},"right":a}}
ctnew={"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"new"}}
def jump(t): return {"jump":{"target":t}}
def goto(t): return {"goto":{"target":t}}
def concat3(): return {"concat":[{"payload":{"protocol":"ip","field":"daddr"}},{"meta":{"key":"l4proto"}},{"payload":{"protocol":"th","field":"dport"}}]}
def concat2(): return {"concat":[{"meta":{"key":"l4proto"}},{"payload":{"protocol":"th","field":"dport"}}]}
def vmap(key,m): return {"vmap":{"key":key,"data":"@"+m}}
def chain(fam,table,name,**kw):
    c={"family":fam,"table":table,"name":name,"handle":0}
    c.update(kw); add("chain",c)
rules=[]
def rule(fam,table,ch,exprs,comment=None):
    r={"family":fam,"table":table,"chain":ch,"handle":0,"expr":exprs}
    if comment: r["comment"]=comment
    rules.append({"rule":r})
masq=16384
# --- ip kube-proxy ---
add("table",{"family":"ip","name":T,"handle":0,"comment":"rules for kube-proxy"})
if V=="1.31":
    base=[("filter-prerouting","filter","prerouting",-110),("filter-input","filter","input",-110),("filter-forward","filter","forward",-110),
          ("filter-output","filter","output",-110),("filter-output-post-dnat","filter","output",-90),("nat-prerouting","nat","prerouting",-100),
          ("nat-output","nat","output",-100),("nat-postrouting","nat","postrouting",100)]
else: # 1.34 and master: pre-DNAT firewall chains, the others at filter priority, no post-dnat chain
    base=[("filter-prerouting-pre-dnat","filter","prerouting",-110),("filter-output-pre-dnat","filter","output",-110),
          ("filter-input","filter","input",0),("filter-forward","filter","forward",0),("filter-output","filter","output",0),
          ("nat-prerouting","nat","prerouting",-100),("nat-output","nat","output",-100),("nat-postrouting","nat","postrouting",100)]
for n,t,h,p in base: chain("ip",T,n,type=t,hook=h,prio=p,policy="accept")
svcW="service-HVFWP5L3-default/web/tcp/http"; extW="external-HVFWP5L3-default/web/tcp/http"
epW1="endpoint-JG4ARJBS-default/web/tcp/http__10.42.0.9/8080"; epW2="endpoint-5RFYQ4JH-default/web/tcp/http__10.42.0.10/8080"
svcR="service-4AU5WYYR-default/redis/tcp/redis"; epR="endpoint-SW3NKRQW-default/redis/tcp/redis__10.42.0.20/6379"
svcA="service-D4HK2GZN-default/api/tcp/https"; extA="external-D4HK2GZN-default/api/tcp/https"; locA="local-D4HK2GZN-default/api/tcp/https"
epA="endpoint-QQGFXNVL-default/api/tcp/https__10.42.0.21/8443"
affW1="affinity-JG4ARJBS-default/web/tcp/http__10.42.0.9/8080"; affW2="affinity-5RFYQ4JH-default/web/tcp/http__10.42.0.10/8080"
names=["cluster-ips-check","firewall-check","mark-for-masquerade","masquerading","nodeport-endpoints-check","reject-chain","service-endpoints-check","services",
          svcW,extW,epW1,epW2,svcR,epR,svcA,extA,locA,epA]
for n in names:
    if V=="master" and n.startswith("endpoint-"):
        continue
    chain("ip",T,n)
if V=="1.34":
    for a in (affW1,affW2):
        add("set",{"family":"ip","name":a,"table":T,"type":"ipv4_addr","handle":0,"flags":["dynamic","timeout"],"timeout":10800})
add("set",{"family":"ip","name":"cluster-ips","table":T,"type":"ipv4_addr","handle":0,"comment":"Active ClusterIPs","elem":["10.43.12.34","10.43.20.1","10.43.30.5","10.43.50.9"]})
add("set",{"family":"ip","name":"nodeport-ips","table":T,"type":"ipv4_addr","handle":0,"comment":"IPs that accept NodePort traffic","elem":["192.168.5.15"]})
add("map",{"family":"ip","name":"firewall-ips","table":T,"type":["ipv4_addr","inet_proto","inet_service"],"handle":0,"map":"verdict","comment":"destinations that are subject to LoadBalancerSourceRanges"})
add("map",{"family":"ip","name":"no-endpoint-nodeports","table":T,"type":["inet_proto","inet_service"],"handle":0,"map":"verdict","comment":"vmap to drop or reject packets to service nodeports with no endpoints",
  "elem":[[{"concat":["tcp",30999]},goto("reject-chain")]]})
add("map",{"family":"ip","name":"no-endpoint-services","table":T,"type":["ipv4_addr","inet_proto","inet_service"],"handle":0,"map":"verdict","comment":"vmap to drop or reject packets to services with no endpoints",
  "elem":[[{"concat":["10.43.50.9","tcp",80]},goto("reject-chain")]]})
add("map",{"family":"ip","name":"service-ips","table":T,"type":["ipv4_addr","inet_proto","inet_service"],"handle":0,"map":"verdict","comment":"ClusterIP, ExternalIP and LoadBalancer IP traffic",
  "elem":[[{"concat":["10.43.12.34","tcp",80]},goto(svcW)],
          [{"concat":["10.43.20.1","tcp",6379]},goto(svcR)],
          [{"concat":["10.43.30.5","tcp",8443]},goto(svcA)],
          [{"concat":["192.168.5.15","tcp",8443]},goto(extA)]]})
add("map",{"family":"ip","name":"service-nodeports","table":T,"type":["inet_proto","inet_service"],"handle":0,"map":"verdict","comment":"NodePort traffic",
  "elem":[[{"concat":["tcp",30080]},goto(extW)]]})
if V=="1.31":
    rule("ip",T,"filter-prerouting",[ctnew,jump("firewall-check")])
    rule("ip",T,"filter-input",[ctnew,jump("nodeport-endpoints-check")])
    rule("ip",T,"filter-input",[ctnew,jump("service-endpoints-check")])
    rule("ip",T,"filter-forward",[ctnew,jump("service-endpoints-check")])
    rule("ip",T,"filter-forward",[ctnew,jump("cluster-ips-check")])
    rule("ip",T,"filter-output",[ctnew,jump("service-endpoints-check")])
    rule("ip",T,"filter-output",[ctnew,jump("firewall-check")])
    rule("ip",T,"filter-output-post-dnat",[ctnew,jump("cluster-ips-check")])
else:
    rule("ip",T,"filter-input",[ctnew,jump("nodeport-endpoints-check")])
    rule("ip",T,"filter-input",[ctnew,jump("service-endpoints-check")])
    rule("ip",T,"filter-forward",[ctnew,jump("service-endpoints-check")])
    rule("ip",T,"filter-output",[ctnew,jump("service-endpoints-check")])
    rule("ip",T,"filter-prerouting-pre-dnat",[ctnew,jump("firewall-check")])
    rule("ip",T,"filter-output-pre-dnat",[ctnew,jump("firewall-check")])
    rule("ip",T,"filter-forward",[ctnew,jump("cluster-ips-check")])
    rule("ip",T,"filter-output",[ctnew,jump("cluster-ips-check")])
rule("ip",T,"nat-prerouting",[jump("services")])
rule("ip",T,"nat-output",[jump("services")])
rule("ip",T,"nat-postrouting",[jump("masquerading")])
rule("ip",T,"cluster-ips-check",[daddr("@cluster-ips"),{"reject":{"type":"icmp","expr":"port-unreachable"}}],"Reject traffic to invalid ports of ClusterIPs")
rule("ip",T,"cluster-ips-check",[daddr({"set":[{"prefix":{"addr":"10.43.0.0","len":16}}]}),{"drop":None}],"Drop traffic to unallocated ClusterIPs")
rule("ip",T,"firewall-check",[vmap(concat3(),"firewall-ips")])
rule("ip",T,"mark-for-masquerade",[{"mangle":{"key":{"meta":{"key":"mark"}},"value":{"|":[{"meta":{"key":"mark"}},masq]}}}])
rule("ip",T,"masquerading",[{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},masq]},"right":0}},{"return":None}])
rule("ip",T,"masquerading",[{"mangle":{"key":{"meta":{"key":"mark"}},"value":{"^":[{"meta":{"key":"mark"}},masq]}}}])
rule("ip",T,"masquerading",[{"masquerade":{"flags":"fully-random"}}])
rule("ip",T,"nodeport-endpoints-check",[daddr("@nodeport-ips"),vmap(concat2(),"no-endpoint-nodeports")])
rule("ip",T,"reject-chain",[{"reject":None}],"helper for @no-endpoint-services / @no-endpoint-nodeports")
rule("ip",T,"service-endpoints-check",[vmap(concat3(),"no-endpoint-services")])
rule("ip",T,"services",[vmap(concat3(),"service-ips")])
rule("ip",T,"services",[daddr("@nodeport-ips"),vmap(concat2(),"service-nodeports")])
def l4tcp(): return {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}}
def numgen(eps):
    return {"vmap":{"key":{"numgen":{"mode":"random","mod":len(eps),"offset":0}},"data":{"set":[[i,goto(e)] for i,e in enumerate(eps)]}}}
def ep(name,ip,port,aff=None):
    rule("ip",T,name,[saddr(ip),jump("mark-for-masquerade")])
    if aff:
        rule("ip",T,name,[{"set":{"op":"update","elem":{"payload":{"protocol":"ip","field":"saddr"}},"set":"@"+aff}}])
    rule("ip",T,name,[l4tcp(),{"dnat":{"addr":ip,"port":port}}])
# web: NodePort 30080, ClusterIP 10.43.12.34:80, two endpoints, Cluster traffic policy
rule("ip",T,svcW,[daddr("10.43.12.34"),tcpd(80),saddr({"prefix":{"addr":"10.42.0.0","len":16}},"!="),jump("mark-for-masquerade")])
if V=="1.34":
    # sessionAffinity: ClientIP. A fresh outside source is in no affinity set.
    rule("ip",T,svcW,[saddr("@"+affW1),goto(epW1)])
    rule("ip",T,svcW,[saddr("@"+affW2),goto(epW2)])
if V=="master":
    # master: several endpoints are one dnat through a numgen map, no endpoint chains.
    rule("ip",T,svcW,[l4tcp(),{"dnat":{"family":"ip","addr":{"map":{"key":{"numgen":{"mode":"random","mod":2,"offset":0}},
        "data":{"set":[[0,{"concat":["10.42.0.9",8080]}],[1,{"concat":["10.42.0.10",8080]}]]}}},"type_flags":["addr . port"]}}])
else:
    rule("ip",T,svcW,[numgen([epW1,epW2])])
rule("ip",T,extW,[jump("mark-for-masquerade")],"masquerade traffic from outside the cluster")
rule("ip",T,extW,[goto(svcW)])
if V=="1.34":
    ep(epW1,"10.42.0.9",8080,affW1); ep(epW2,"10.42.0.10",8080,affW2)
elif V!="master":
    ep(epW1,"10.42.0.9",8080); ep(epW2,"10.42.0.10",8080)
# redis: ClusterIP only
rule("ip",T,svcR,[daddr("10.43.20.1"),tcpd(6379),saddr({"prefix":{"addr":"10.42.0.0","len":16}},"!="),jump("mark-for-masquerade")])
if V=="master":
    rule("ip",T,svcR,[l4tcp(),{"dnat":{"addr":"10.42.0.20","port":6379}}])
else:
    rule("ip",T,svcR,[numgen([epR])])
    ep(epR,"10.42.0.20",6379)
# api: externalIPs: [192.168.5.15] (the node's address), externalTrafficPolicy Local
fibsaddr={"match":{"op":"==","left":{"fib":{"result":"type","flags":["saddr"]}},"right":"local"}}
rule("ip",T,svcA,[daddr("10.43.30.5"),tcpd(8443),saddr({"prefix":{"addr":"10.42.0.0","len":16}},"!="),jump("mark-for-masquerade")])
if V=="master":
    rule("ip",T,svcA,[l4tcp(),{"dnat":{"addr":"10.42.0.21","port":8443}}])
else:
    rule("ip",T,svcA,[numgen([epA])])
rule("ip",T,extA,[saddr({"prefix":{"addr":"10.42.0.0","len":16}}),goto(svcA)],"short-circuit pod traffic")
rule("ip",T,extA,[fibsaddr,jump("mark-for-masquerade")],"masquerade local traffic")
rule("ip",T,extA,[fibsaddr,goto(svcA)],"short-circuit local traffic")
rule("ip",T,extA,[goto(locA)])
if V=="master":
    rule("ip",T,locA,[l4tcp(),{"dnat":{"addr":"10.42.0.21","port":8443}}])
else:
    rule("ip",T,locA,[numgen([epA])])
    ep(epA,"10.42.0.21",8443)
out.extend(rules); rules=[]
# --- ip6 kube-proxy: a single-stack IPv4 cluster still creates it (empty maps) ---
add("table",{"family":"ip6","name":T,"handle":0,"comment":"rules for kube-proxy"})
for n,t,h,p in base: chain("ip6",T,n,type=t,hook=h,prio=p,policy="accept")
chain("ip6",T,"services")
add("map",{"family":"ip6","name":"service-ips","table":T,"type":["ipv6_addr","inet_proto","inet_service"],"handle":0,"map":"verdict"})
add("map",{"family":"ip6","name":"service-nodeports","table":T,"type":["inet_proto","inet_service"],"handle":0,"map":"verdict"})
add("set",{"family":"ip6","name":"nodeport-ips","table":T,"type":"ipv6_addr","handle":0})
rule("ip6",T,"nat-prerouting",[jump("services")])
rule("ip6",T,"services",[{"vmap":{"key":{"concat":[{"payload":{"protocol":"ip6","field":"daddr"}},{"meta":{"key":"l4proto"}},{"payload":{"protocol":"th","field":"dport"}}]},"data":"@service-ips"}}])
rule("ip6",T,"services",[{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"daddr"}},"right":"@nodeport-ips"}},vmap(concat2(),"service-nodeports")])
out.extend(rules); rules=[]
# --- ip cni_hostport: the CNI portmap plugin's nftables backend (a hostPort) ---
H="cni_hostport"
add("table",{"family":"ip","name":H,"handle":0})
chain("ip",H,"prerouting",type="nat",hook="prerouting",prio=-100,policy="accept")
chain("ip",H,"output",type="nat",hook="output",prio=-100,policy="accept")
chain("ip",H,"masquerading",type="nat",hook="postrouting",prio=100,policy="accept")
for n in ["hostports","hostports_all","hostip_hostports"]: chain("ip",H,n)
fibd={"match":{"op":"==","left":{"fib":{"result":"type","flags":["daddr"]}},"right":"local"}}
rule("ip",H,"prerouting",[fibd,jump("hostports_all")])
rule("ip",H,"output",[fibd,jump("hostports_all")])
rule("ip",H,"hostports_all",[jump("hostip_hostports")])
rule("ip",H,"hostports_all",[jump("hostports")])
rule("ip",H,"hostports",[tcpd(8088),{"dnat":{"addr":"10.42.0.12","port":80}}],"0f3e1c2a9b8d")
rule("ip",H,"hostports",[daddr("192.168.5.15"),{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":5353}},{"dnat":{"addr":"10.42.0.12","port":53}}],"0f3e1c2a9b8d")
rule("ip",H,"masquerading",[saddr("10.42.0.12"),daddr("10.42.0.12"),{"masquerade":None}])
rule("ip",H,"masquerading",[saddr("127.0.0.1"),daddr("10.42.0.12"),{"masquerade":None}])
out.extend(rules)
sys.stdout.write('{"nftables": [\n'+',\n'.join(json.dumps(o,separators=(', ',': ')) for o in out)+'\n]}\n')
