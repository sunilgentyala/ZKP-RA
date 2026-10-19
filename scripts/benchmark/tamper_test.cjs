const snarkjs=require("snarkjs"),fs=require("fs");
(async()=>{
 const vk=JSON.parse(fs.readFileSync("outold/vk.json"));
 const input=JSON.parse(fs.readFileSync("C:/Gitrepos/ZKP-RA/build/input.json"));
 const {proof,publicSignals}=await snarkjs.groth16.fullProve(input,"outold/old_js/old.wasm","outold/z1.zkey");
 console.log("honest verifies:",await snarkjs.groth16.verify(vk,publicSignals,proof));
 console.log("public signal order:",publicSignals.length);
 for(let i=0;i<publicSignals.length;i++){const ps=[...publicSignals];ps[i]=(BigInt(ps[i])+1n).toString();console.log("tampered public input",i,"verifies:",await snarkjs.groth16.verify(vk,ps,proof));}
 const p2=JSON.parse(JSON.stringify(proof));p2.pi_a[0]=(BigInt(p2.pi_a[0])+1n).toString();
 let r;try{r=await snarkjs.groth16.verify(vk,publicSignals,p2)}catch(e){r="error/rejected"}console.log("tampered proof point A verifies:",r);
 for(const [k,v] of [["ctx",0],["state",3],["inp",2]]){const b=JSON.parse(JSON.stringify(input));b[k][v]="424242";let rej=false;try{await snarkjs.groth16.fullProve(b,"outold/old_js/old.wasm","outold/z1.zkey")}catch(e){rej=true}console.log("poisoned",k,"chunk -> proof generation refused:",rej);}
 const b2=JSON.parse(JSON.stringify(input));b2.tx_amount="5000000000000000000000";let rej2=false;try{await snarkjs.groth16.fullProve(b2,"outold/old_js/old.wasm","outold/z1.zkey")}catch(e){rej2=true}console.log("amount above policy cap -> proof generation refused:",rej2);
process.exit(0);})();
