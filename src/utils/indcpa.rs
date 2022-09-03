use crate::error::KyberError;
use crate::services::kyber::*;
use crate::services::Keys;
use crate::utils::poly::Poly;

use rand::{rngs::OsRng, RngCore};
use sha3::{Digest, Sha3_512};
pub(crate) struct Indcpa {
    pub poly: Poly,
}

impl Indcpa {
    pub(crate) fn new(paramsK: u64) -> Self {
        Indcpa {
            poly: Poly::new(paramsK),
        }
    }

    pub(crate) fn indcpaKeyGen(&self) -> Result<Keys, KyberError> {
        let mut rnd = [0u8; paramsSymBytes];
        OsRng.fill_bytes(&mut rnd);

        // hash rnd with SHA3-512
        let mut hasher: Sha3_512 = Sha3_512::new();
        hasher.update(rnd);
        //let mut seed: sha3::Digest = Digest::digest(hasher.finalize());
        let seed = hasher.finalize();
        //Digest::new();
        //let seed = hash1.digest();
        let public_seed_buf = &seed.as_slice()[0..paramsSymBytes];
        let noise_seed_buf = &seed.as_slice()[paramsSymBytes..(paramsSymBytes * 2)];
        let public_seed = public_seed_buf.to_vec();
        let noise_seed = noise_seed_buf.to_vec();
        // generate public matrix A (already in NTT form)
        let a = Indcpa::generate_matrix(&public_seed, false);
        let mut s = Vec::<Vec<u8>>::new(); //this.paramsK
        let mut e = Vec::<Vec<u8>>::new(); // this.paramsK
        for i in 0..self.poly.get_paramsK() {
            s.push(
                self.poly
                    .get_noise_poly(&noise_seed, i, self.poly.get_paramsK()),
            );
            e.push(self.poly.get_noise_poly(
                &noise_seed,
                i + self.poly.get_paramsK(),
                self.poly.get_paramsK(),
            ));
        }
        s.iter_mut().for_each(|n| *n = Poly::ntt(n));
        e.iter_mut().for_each(|n| *n = Poly::ntt(n));
        s.iter_mut().for_each(|n| *n = Poly::poly_reduce(n));

        let mut pk = Vec::<Vec<u8>>::new(); // this.paramsK
        for i in 0..self.poly.get_paramsK() {
            pk.push(Poly::polyToMont(&Poly::polyVectorPointWiseAccMont(
                &a[i as usize],
                &s,
            )));
        }

        pk.iter_mut()
            .enumerate()
            .for_each(|n| *n.1 = Poly::polyAdd(&n.1, &e[n.0]));
        pk.iter_mut().for_each(|n| *n = Poly::poly_reduce(n));

        // PUBLIC KEY
        // turn polynomials into byte arrays
        let mut public = Vec::<u8>::new();
        let mut bytes = Vec::<u8>::new();

        for i in 0..self.poly.get_paramsK() {
            bytes = Poly::polyToBytes(&pk[i as usize]);
            bytes.iter().for_each(|n| public.push(*n))
        }
        public_seed.iter().for_each(|n| public.push(*n));

        // PRIVATE KEY
        let mut private = Vec::<u8>::new();
        let mut bytes = Vec::<u8>::new();
        for i in 0..self.poly.get_paramsK() {
            bytes = Poly::polyToBytes(&s[i as usize]);
            for j in 0..bytes.len() {
                private.push(bytes[j])
            }
        }

        Ok(Keys::new(&private, &public))
    }

    ///Encrypt the given message using the Kyber public-key encryption scheme
    pub(crate) fn indcpaEncrypt(
        &self,
        publicKey: &Vec<u8>,
        msg: &Vec<u8>,
        coins: &Vec<u8>,
    ) -> Result<Vec<u8>, KyberError> {
        /*
        const pk: number[][] = [];
        let start;
        let end;
        // decode message m
        let k = this.poly.polyFromData(msg);
        for (let i = 0; i < this.paramsK; i++) {
            start = (i * KyberService.paramsPolyBytes);
            end = (i + 1) * KyberService.paramsPolyBytes;
            pk[i] = this.poly.polyFromBytes(publicKey.slice(start, end));
        }
        let seed;
        switch (this.paramsK) {
            case 2:
                seed = publicKey.slice(KyberService.paramsPolyvecBytesK512, KyberService.paramsIndcpaPublicKeyBytesK512);
                break;
            case 3:
                seed = publicKey.slice(KyberService.paramsPolyvecBytesK768, KyberService.paramsIndcpaPublicKeyBytesK768);
                break;
            default:
                seed = publicKey.slice(KyberService.paramsPolyvecBytesK1024, KyberService.paramsIndcpaPublicKeyBytesK1024);
        }
        const at = this.generateMatrix(seed, true);
        const sp: number[][] = []; // this.paramsK
        const ep: number[][] = []; // this.paramsK
        for (let i = 0; i < this.paramsK; i++) {
            sp[i] = this.poly.getNoisePoly(coins, i, this.paramsK);
            ep[i] = this.poly.getNoisePoly(coins, i + this.paramsK, 3);
        }
        let epp: number[] = this.poly.getNoisePoly(coins, (this.paramsK * 2), 3);

        for (let i = 0; i < this.paramsK; i++) {
            sp[i] = this.poly.ntt(sp[i]);
        }
        for (let i = 0; i < this.paramsK; i++) {
            sp[i] = this.poly.polyReduce(sp[i]);
        }

        let bp: number[][] = []; // this.paramsK
        for (let i = 0; i < this.paramsK; i++) {
            bp[i] = this.poly.polyVectorPointWiseAccMont(at[i], sp);
        }
        let v = this.poly.polyVectorPointWiseAccMont(pk, sp);
        bp = this.poly.polyVectorInvNTTMont(bp);
        v = this.poly.invNTT(v);
        bp = this.poly.polyVectorAdd(bp, ep);
        v = this.poly.polyAdd(v, epp);
        v = this.poly.polyAdd(v, k);
        bp = this.poly.polyVectorReduce(bp);
        v = this.poly.polyReduce(v);
        const bCompress = this.poly.compressPolyVector(bp);
        const vCompress = this.poly.compressPoly(v);
        const c3: number[] = [];
        for (let i = 0; i < bCompress.length; ++i) {
            c3[i] = bCompress[i];
        }
        for (let i = 0; i < vCompress.length; ++i) {
            c3[i + bCompress.length] = vCompress[i];
        }
        return c3;
         */
        Ok(Vec::<u8>::new())
    }

    /// Decrypt the given byte array using the Kyber public-key encryption scheme    
    pub(crate) fn indcpaDecrypt(packedCipherText: Vec<u8>, privateKey: Vec<u8>) -> Vec<u8> {
        /*
            let bpEndIndex = 0
            let vEndIndex = 0
            switch (this.paramsK) {
                case 2:
                    bpEndIndex = KyberService.paramsPolyvecCompressedBytesK512;
                    vEndIndex = bpEndIndex + KyberService.paramsPolyCompressedBytesK512;
                    break;
                case 3:
                    bpEndIndex = KyberService.paramsPolyvecCompressedBytesK768;
                    vEndIndex = bpEndIndex + KyberService.paramsPolyCompressedBytesK768;
                    break;
                default:
                    bpEndIndex = KyberService.paramsPolyvecCompressedBytesK1024;
                    vEndIndex = bpEndIndex + KyberService.paramsPolyCompressedBytesK1024;
            }

            let bp = this.poly.decompressPolyVector(packedCipherText.slice(0, bpEndIndex));
            const v = this.poly.decompressPoly(packedCipherText.slice(bpEndIndex, vEndIndex));

            const privateKeyPolyvec = this.poly.polyVectorFromBytes(privateKey);
            bp = this.poly.polyVectorNTT(bp);

            let mp = this.poly.polyVectorPointWiseAccMont(privateKeyPolyvec, bp);

            mp = this.poly.invNTT(mp);
            mp = this.poly.subtract(v, mp);
            mp = this.poly.polyReduce(mp);
            return this.poly.polyToMsg(mp);
        */
        Vec::<u8>::new()
    }

    /// Generate a polynomial vector matrix from the given seed
    fn generate_matrix(public_seed: &Vec<u8>, bool: bool) -> Vec<Vec<Vec<u8>>> {
        Vec::<Vec<Vec<u8>>>::new()
        /*
        let a: number[][][] = []; //this.paramsK)
        let output: number[] = []; // 3 * 168
        const xof = new SHAKE(128);
        let ctr = 0;
        for (let i = 0; i < this.paramsK; i++) {
            a[i] = []; // this.paramsK
            let transpose: number[] = []; // 2
            for (let j = 0; j < this.paramsK; j++) {
                // set if transposed matrix or not
                transpose[0] = j;
                transpose[1] = i;
                if (transposed) {
                    transpose[0] = i;
                    transpose[1] = j;
                }
                // obtain xof of (seed+i+j) or (seed+j+i) depending on above code
                // output is 672 bytes in length
                xof.reset();
                const buffer1 = Buffer.from(seed);
                const buffer2 = Buffer.from(transpose);
                xof.update(buffer1).update(buffer2);
                let outputString = xof.digest({format: "binary", buffer: Buffer.alloc(672)});
                let output = new Buffer(outputString.length);
                output.fill(outputString);
                // run rejection sampling on the output from above
                let outputlen = 3 * 168; // 504
                let result: any[] = []; // 2
                result = this.generateUniform(output.slice(0, 504), outputlen, KyberService.paramsN);
                a[i][j] = result[0]; // the result here is an NTT-representation
                ctr = result[1]; // keeps track of index of output array from sampling function
                while (ctr < KyberService.paramsN) { // if the polynomial hasnt been filled yet with mod q entries
                    const outputn = output.slice(504, 672); // take last 168 bytes of byte array from xof
                    let result1: any[] = []; //2
                    result1 = this.generateUniform(outputn, 168, KyberService.paramsN - ctr); // run sampling function again
                    let missing = result1[0]; // here is additional mod q polynomial coefficients
                    let ctrn = result1[1]; // how many coefficients were accepted and are in the output
                    // starting at last position of output array from first sampling function until 256 is reached
                    for (let k = ctr; k < KyberService.paramsN; k++) {
                        a[i][j][k] = missing[k - ctr]; // fill rest of array with the additional coefficients until full
                    }
                    ctr = ctr + ctrn; // update index
                }

            }
        }
        return a;
        */
    }
}
