const snarkjs=require("snarkjs"),fs=require("fs"),{execSync}=require("child_process"),os=require("os");
const {buildPoseidon}=require("circomlibjs");
const N=+process.env.TRIALS||100;
function med(a){const s=[...a].sort((x,y)=>x-y),m=s.length>>1;return s.length%2?s[m]:(s[m-1]+s[m])/2}
function pct(a,p){const s=[...a].sort((x,y)=>x-y);return s[Math.min(s.length-1,Math.ceil(p*s.length)-1)]}
(async()=>{
 const P=await buildPoseidon(),F=P.F;
 function pc(ch,D){let cap=BigInt(D);const n=ch.length,r=Math.floor((n+1)/2);for(let i=0;i<r;i++){const a=2*i<n?ch[2*i]:0n,b=2*i+1<n?ch[2*i+1]:0n;cap=F.toObject(P([cap,a,b]));}return cap}
 const cfgs=JSON.parse(process.argv[2]); const out=[];
 for(const c of cfgs){ // {name,dir,wasmName,k,ptau}
  const nc=8*c.k,ns=8*c.k,ni=4*c.k;
  const ctx=[...Array(nc)].map((_,i)=>BigInt(i+1)),st=[...Array(ns)].map((_,i)=>BigInt(i+11)),inp=[...Array(ni)].map((_,i)=>BigInt(i+21));
  const H=F.toObject(P([pc(ctx,1),pc(st,2),pc(inp,3)]));
  const rp=12345n,salt=67890n,rh=F.toObject(P([rp,salt]));
  const input={H_t:H.toString(),tx_recipient:"999",tx_amount:"500000000000000000000",tx_slippage_bps:"50",tx_router_hash:rh.toString(),ctx:ctx.map(String),state:st.map(String),inp:inp.map(String),router_preimage:"12345",witness_salt:"67890"};
  const r1=`${c.dir}/${c.base}.r1cs`,z0=`${c.dir}/z0.zkey`,z1=`${c.dir}/z1.zkey`,vk=`${c.dir}/vk.json`;
  const sj=`node node_modules/snarkjs/build/cli.cjs`;
  const info=execSync(`${sj} r1cs info ${r1}`).toString(); const cons=+info.match(/Constraints: (\d+)/)[1];
  execSync(`${sj} groth16 setup ${r1} ${c.ptau} ${z0}`,{stdio:"ignore"});
  execSync(`${sj} zkey contribute ${z0} ${z1} --name=bench -e="bench-entropy-${c.name}"`,{stdio:"ignore"});
  execSync(`${sj} zkey export verificationkey ${z1} ${vk}`,{stdio:"ignore"});
  const wasm=`${c.dir}/${c.base}_js/${c.base}.wasm`;
  const tot=[],wit=[]; let pr,pub;
  for(let i=0;i<N;i++){const t0=process.hrtime.bigint();const o=await snarkjs.groth16.fullProve(input,wasm,z1);tot.push(Number(process.hrtime.bigint()-t0)/1e6);pr=o.proof;pub=o.publicSignals;}
  const ok=await snarkjs.groth16.verify(JSON.parse(fs.readFileSync(vk)),pub,pr);
  // poisoned-input check: flip one context chunk, witness generation must fail
  let poisonRejected=false;const bad=JSON.parse(JSON.stringify(input));bad.ctx[0]="999999";
  try{await snarkjs.groth16.fullProve(bad,wasm,z1);}catch(e){poisonRejected=true}
  const res={name:c.name,k:c.k,constraints:cons,chunks:nc+ns+ni,trials:N,median:med(tot),min:Math.min(...tot),max:Math.max(...tot),p95:pct(tot,0.95),p99:pct(tot,0.99),verifies:ok,poisonRejected};
  console.log(JSON.stringify(res)); out.push(res);
 }
 console.log("CPU",os.cpus()[0].model,os.cpus().length,process.version);
 fs.writeFileSync("results.json",JSON.stringify(out,null,1));
})();
