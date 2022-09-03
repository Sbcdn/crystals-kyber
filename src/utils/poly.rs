use super::byteops::ByteOps;

pub(crate) struct Poly {
    byteOps: ByteOps,
}

impl Poly {
    pub(crate) fn new(paramsK: u64) -> Self {
        Poly {
            byteOps: ByteOps::new(paramsK),
        }
    }

    pub(crate) fn get_paramsK(&self) -> u64 {
        self.byteOps.paramsK
    }

    pub(crate) fn get_noise_poly(&self, seed: &Vec<u8>, i: u64, paramsK: u64) -> Vec<u8> {
        Vec::<u8>::new()
    }

    pub(crate) fn ntt(vec: &Vec<u8>) -> Vec<u8> {
        Vec::<u8>::new()
    }

    pub(crate) fn poly_reduce(vec: &Vec<u8>) -> Vec<u8> {
        Vec::<u8>::new()
    }

    pub(crate) fn polyToMont(vec: &Vec<u8>) -> Vec<u8> {
        Vec::<u8>::new()
    }
    pub(crate) fn polyVectorPointWiseAccMont(vec: &Vec<Vec<u8>>, s: &Vec<Vec<u8>>) -> Vec<u8> {
        Vec::<u8>::new()
    }

    pub(crate) fn polyAdd(pk: &Vec<u8>, e: &Vec<u8>) -> Vec<u8> {
        Vec::<u8>::new()
    }

    pub(crate) fn polyToBytes(bytes: &Vec<u8>) -> Vec<u8> {
        Vec::<u8>::new()
    }
}
