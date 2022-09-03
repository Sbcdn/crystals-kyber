use crate::{
    error::{self, KyberError},
    utils::indcpa::Indcpa,
};
use rand::{rngs::OsRng, RngCore};
use serde_json::map::Keys;
use sha3::{
    digest::{ExtendableOutput, XofReader},
    Digest, Sha3_256, Sha3_512, Shake256,
};

pub(crate) struct KyberService {
    indcpa: Indcpa,
}

pub(crate) const nttZetas: [usize; 128] = [
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962, 2127, 1855, 1468, 573,
    2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017, 732, 608, 1787, 411, 3124, 1758, 1223, 652,
    2777, 1015, 2036, 1491, 3047, 1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239,
    3058, 830, 107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226, 430, 555,
    843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574, 1653, 3083, 778, 1159, 3182,
    2552, 1483, 2727, 1119, 1739, 644, 2457, 349, 418, 329, 3173, 3254, 817, 1097, 603, 610, 1322,
    2044, 1864, 384, 2114, 3193, 1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819,
    2475, 2459, 478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628,
];

pub(crate) const nttZetasInv: [usize; 128] = [
    1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535, 1278, 1530, 1185,
    1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,
    75, 156, 3000, 2911, 2980, 872, 2685, 1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676,
    1755, 460, 291, 235, 3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275,
    2652, 1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853, 1860, 3203,
    1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552, 2677, 2106, 1571, 205, 2918,
    1542, 2721, 2597, 2312, 681, 130, 1602, 1871, 829, 2946, 3065, 1325, 2756, 1861, 1474, 1202,
    2367, 3147, 1752, 2707, 171, 3127, 3042, 1907, 1836, 1517, 359, 758, 1441,
];

pub(crate) const paramsN: usize = 256;
pub(crate) const paramsQ: usize = 3329;
pub(crate) const paramsQinv: usize = 62209;
pub(crate) const paramsSymBytes: usize = 32;
pub(crate) const paramsPolyBytes: usize = 384;
pub(crate) const paramsETAK512: usize = 3;
pub(crate) const paramsETAK768K1024: usize = 2;
pub(crate) const paramsPolyvecBytesK512: usize = 2 * paramsPolyBytes;
pub(crate) const paramsPolyvecBytesK768: usize = 3 * paramsPolyBytes;
pub(crate) const paramsPolyvecBytesK1024: usize = 4 * paramsPolyBytes;
pub(crate) const paramsPolyCompressedBytesK512: usize = 128;
pub(crate) const paramsPolyCompressedBytesK768: usize = 128;
pub(crate) const paramsPolyCompressedBytesK1024: usize = 160;
pub(crate) const paramsPolyvecCompressedBytesK512: usize = 2 * 320;
pub(crate) const paramsPolyvecCompressedBytesK768: usize = 3 * 320;
pub(crate) const paramsPolyvecCompressedBytesK1024: usize = 4 * 352;
pub(crate) const paramsIndcpaPublicKeyBytesK512: usize = paramsPolyvecBytesK512 + paramsSymBytes;
pub(crate) const paramsIndcpaPublicKeyBytesK768: usize = paramsPolyvecBytesK768 + paramsSymBytes;
pub(crate) const paramsIndcpaPublicKeyBytesK1024: usize = paramsPolyvecBytesK1024 + paramsSymBytes;
pub(crate) const paramsIndcpaSecretKeyBytesK512: usize = 2 * paramsPolyBytes;
pub(crate) const paramsIndcpaSecretKeyBytesK768: usize = 3 * paramsPolyBytes;
pub(crate) const paramsIndcpaSecretKeyBytesK1024: usize = 4 * paramsPolyBytes;

// Kyber512SKBytes is a constant representing the byte length of private keys in Kyber-512
pub(crate) const Kyber512SKBytes: usize =
    paramsPolyvecBytesK512 + ((paramsPolyvecBytesK512 + paramsSymBytes) + 2 * paramsSymBytes);

// Kyber768SKBytes is a constant representing the byte length of private keys in Kyber-768
pub(crate) const Kyber768SKBytes: usize =
    paramsPolyvecBytesK768 + ((paramsPolyvecBytesK768 + paramsSymBytes) + 2 * paramsSymBytes);

// Kyber1024SKBytes is a constant representing the byte length of private keys in Kyber-1024
pub(crate) const Kyber1024SKBytes: usize =
    paramsPolyvecBytesK1024 + ((paramsPolyvecBytesK1024 + paramsSymBytes) + 2 * paramsSymBytes);

// Kyber512PKBytes is a constant representing the byte length of pub(crate) const keys in Kyber-512
pub(crate) const Kyber512PKBytes: usize = paramsPolyvecBytesK512 + paramsSymBytes;

// Kyber768PKBytes is a constant representing the byte length of pub(crate) const keys in Kyber-768
pub(crate) const Kyber768PKBytes: usize = paramsPolyvecBytesK768 + paramsSymBytes;

// Kyber1024PKBytes is a constant representing the byte length of pub(crate) const keys in Kyber-1024
pub(crate) const Kyber1024PKBytes: usize = paramsPolyvecBytesK1024 + paramsSymBytes;

// KyberEncoded512PKBytes is a constant representing the byte length of encoded pub(crate) const keys in Kyber-512
pub(crate) const KyberEncoded512PKBytes: usize = 967;

// KyberEncoded768PKBytes is a constant representing the byte length of encoded pub(crate) const keys in Kyber-768
pub(crate) const KyberEncoded768PKBytes: usize = 1351;

// KyberEncoded1024PKBytes is a constant representing the byte length of encoded pub(crate) const keys in Kyber-1024
pub(crate) const KyberEncoded1024PKBytes: usize = 1735;

// Kyber512CTBytes is a constant representing the byte length of ciphertexts in Kyber-512
pub(crate) const Kyber512CTBytes: usize =
    paramsPolyvecCompressedBytesK512 + paramsPolyCompressedBytesK512;

// Kyber768CTBytes is a constant representing the byte length of ciphertexts in Kyber-768
pub(crate) const Kyber768CTBytes: usize =
    paramsPolyvecCompressedBytesK768 + paramsPolyCompressedBytesK768;

// Kyber1024CTBytes is a constant representing the byte length of ciphertexts in Kyber-1024
pub(crate) const Kyber1024CTBytes: usize =
    paramsPolyvecCompressedBytesK1024 + paramsPolyCompressedBytesK1024;

// KyberEncoded512CTBytes is a constant representing the byte length of Encoded ciphertexts in Kyber-512
pub(crate) const KyberEncoded512CTBytes: usize = 935;

// KyberEncoded768CTBytes is a constant representing the byte length of Encoded ciphertexts in Kyber-768
pub(crate) const KyberEncoded768CTBytes: usize = 1255;

// KyberEncoded1024CTBytes is a constant representing the byte length of Encoded ciphertexts in Kyber-1024
pub(crate) const KyberEncoded1024CTBytes: usize = 1735;

// KyberSSBytes is a constant representing the byte length of shared secrets in Kyber
pub(crate) const KyberSSBytes: usize = 32;

// KyberEncodedSSBytes is a constant representing the byte length of encoded shared secrets in Kyber
pub(crate) const KyberEncodedSSBytes: usize = 193;

impl KyberService {
    pub fn new(paramsK: usize) -> Self {
        KyberService {
            indcpa: Indcpa::new(paramsK as u64),
        }
    }
    /// Generate local Kyber Keys
    pub fn generate_kyber_keys(&self) -> Result<super::Keys, error::KyberError> {
        // IND-CPA keypair
        let indcpakeys = self.indcpa.indcpaKeyGen()?;
        let mut sk = indcpakeys.private;

        // FO transform to make IND-CCA2
        // get hash of pk
        let mut hash1 = Sha3_256::new();
        hash1.update(&indcpakeys.public);
        let pkh: Vec<u8> = hash1.finalize().to_vec();

        // read 32 random values (0-255) into a 32 byte array
        let mut rnd = [0u8; paramsSymBytes];
        OsRng.fill_bytes(&mut rnd);

        // concatenate to form IND-CCA2 private key: sk + pk + h(pk) + rnd
        indcpakeys.public.iter().for_each(|n| sk.push(*n));
        pkh.iter().for_each(|n| sk.push(*n));
        rnd.iter().for_each(|n| sk.push(*n));

        Ok(super::Keys::new(&sk, &indcpakeys.public))
    }

    /// Generate a shared secret and cipher text from the given

    pub fn encrypt(&self, public_key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), KyberError> {
        // random 32 bytes
        let mut m = [0u8; paramsSymBytes];
        OsRng.fill_bytes(&mut m);

        // hash m with SHA3-256
        let mut hash1 = Sha3_256::new();
        hash1.update(&m);
        let mh: Vec<u8> = hash1.finalize().to_vec();

        // hash pk with SHA3-256
        let mut hash2 = Sha3_256::new();
        hash2.update(&public_key);
        let pkh: Vec<u8> = hash2.finalize().to_vec();

        // hash mh and pkh with SHA3-512
        let mut hash3 = Sha3_512::new();
        hash3.update(&mh);
        hash3.update(&pkh);
        let kr: Vec<u8> = hash3.finalize().to_vec();
        let kr1 = kr.as_slice()[0..paramsSymBytes].to_vec();
        let kr2 = kr.as_slice()[paramsSymBytes..kr.len()].to_vec();

        // generate ciphertext c
        let cipher_text = self.indcpa.indcpaEncrypt(&public_key, &mh, &kr2)?;
        // hash ciphertext with SHA3-256
        let mut hash4 = Sha3_512::new();
        hash4.update(&cipher_text);
        let ch = hash4.finalize().to_vec();

        // hash kr1 and ch with SHAKE-256
        let mut hash5 = Shake256::default();
        sha3::digest::Update::update(&mut hash5, &kr1);
        sha3::digest::Update::update(&mut hash5, &ch);
        let mut ssBuf = hash5.finalize_xof();
        let mut sharedSecret = [0u8; paramsSymBytes];
        ssBuf.read(&mut sharedSecret);

        Ok((cipher_text, sharedSecret.to_vec()))
    }

    /// Decrypt the given cipher text to create the same shared secret with
    pub fn decrypt(cipher_text: Vec<u8>, private_key: Vec<u8>) -> Vec<u8> {
        /*

        // extract sk, pk, pkh and z
        let startIndex = 0;
        let endIndex = 0;
        switch (this.paramsK) {
            case 2:
                endIndex = KyberService.paramsIndcpaSecretKeyBytesK512;
                break;
            case 3:
                endIndex = KyberService.paramsIndcpaSecretKeyBytesK768;
                break;
            default:
                endIndex = KyberService.paramsIndcpaSecretKeyBytesK1024;
        }

        const indcpaPrivateKey = privateKey.slice(startIndex, endIndex); // indcpa secret key
        startIndex = endIndex;
        switch (this.paramsK) {
            case 2:
                endIndex += KyberService.paramsIndcpaPublicKeyBytesK512;
                break;
            case 3:
                endIndex += KyberService.paramsIndcpaPublicKeyBytesK768;
                break;
            default:
                endIndex += KyberService.paramsIndcpaPublicKeyBytesK1024;
        }
        const indcpaPublicKey = privateKey.slice(startIndex, endIndex); // indcpa public key
        startIndex = endIndex;
        endIndex += KyberService.paramsSymBytes;
        const pkh = privateKey.slice(startIndex, endIndex); // sha3-256 hash
        startIndex = endIndex;
        endIndex += KyberService.paramsSymBytes;
        const z = privateKey.slice(startIndex, endIndex);
        // IND-CPA decrypt
        const m = this.indcpa.indcpaDecrypt(cipherText, indcpaPrivateKey);
        // hash m and pkh with SHA3-512
        const buffer1 = Buffer.from(m);
        const buffer2 = Buffer.from(pkh);
        const hash1 = new SHA3(512);
        hash1.update(buffer1).update(buffer2);
        const krBuf = hash1.digest();
        const kr: number[] = [];
        for (const num of krBuf) {
            kr.push(num);
        }
        const kr1 = krBuf.slice(0, KyberService.paramsSymBytes);
        const kr2Buf = krBuf.slice(KyberService.paramsSymBytes, kr.length);
        const kr2: number[] = [];
        for (const num of kr2Buf) {
            kr2.push(num);
        }
        // IND-CPA encrypt
        const cmp = this.indcpa.indcpaEncrypt(indcpaPublicKey, m, kr2);
        // compare c and cmp to verify the generated shared secret
        const equal = Utilities.arrayCompare(cipherText, cmp);
        if (equal === 1) {
            // hash c with SHA3-256
            const md = new SHA3(256);
            md.update(Buffer.from(cipherText));
            const krh = md.digest();
            let kyberSKBytes = 0;
            switch (this.paramsK) {
                case 2:
                    kyberSKBytes = KyberService.Kyber512SKBytes;
                    break;
                case 3:
                    kyberSKBytes = KyberService.Kyber768SKBytes;
                    break;
                default:
                    kyberSKBytes = KyberService.Kyber1024SKBytes;
            }

            for (let i = 0; i < KyberService.paramsSymBytes; i++) {
                const length = kyberSKBytes - KyberService.paramsSymBytes + i;
                let skx = privateKey.slice(0, length);
                kr[i] = Utilities.intToByte((kr[i]) ^ ((0) & ((kr[i]) ^ (skx[i]))));
            }
            const tempBuf: number[] = [];
            let ctr = 0;
            for (ctr = 0; ctr < kr.length; ++ctr) {
                tempBuf[ctr] = kr[ctr];
            }
            let ctr2 = 0;
            for (; ctr < krh.length; ++ctr) {
                tempBuf[ctr] = krh[ctr2++];
            }
            const buffer3 = Buffer.from(cipherText);
            const hash2 = new SHA3(256);
            hash2.update(buffer3);
            let ch = hash2.digest();
            const buffer4 = Buffer.from(kr1);
            const buffer5 = Buffer.from(ch);
            const hash3 = new SHAKE(256);
            hash3.update(buffer4).update(buffer5);
            const ssBuf = hash3.digest();
            const sharedSecret: number[] = [];
            for (let i = 0; i < KyberService.paramsSymBytes; ++i) {
                sharedSecret[i] = ssBuf[i];
            }
            return sharedSecret;
        } else {
            console.log("Cipher text mis-match");
            return null;
        }
        */
        Vec::<u8>::new()
    }
}
