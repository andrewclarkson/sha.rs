#![feature(asm)]
#![crate_id="sha"]

use std::slice::bytes::copy_memory;

static MAGIC_VALUES_SHA256: [u32, ..8] = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
];

static ROUND_CONSTANTS: [u32, ..64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

pub struct Sha256<'a> {
    state: &'a [u32],
    position: uint,
    buffer: Vec<u8>
}

impl<'a> Sha256<'a> {
    pub fn new() -> Sha256<'a> {
        let mut buffer = Vec::with_capacity(64);
        unsafe { buffer.set_len(64); }
        Sha256 {
            state: MAGIC_VALUES_SHA256.clone(),
            buffer: buffer,
            position: 0,
        }
    }

    //
    // Adds the message to the buffer and hashes when the 
    // buffer is full
    // TODO: refactor
    //
    pub fn update(&mut self, message: &[u8]) {
        
        let mut position: uint = 0;

        if self.position > 0 {
            let space = 64 - self.position;
            if space > message.len() {
                {
                    let destination = self.buffer.mut_slice_from(self.position);
                    copy_memory(destination, message);
                }
                self.position += message.len();
                return;
            } else if space == message.len() {
                {
                    let destination = self.buffer.mut_slice_from(self.position);
                    copy_memory(destination, message);
                }
                self.hash();
                return; 
            } else {
                {
                    let destination = self.buffer.mut_slice_from(self.position);
                    let source = message.slice_to(space);
                    copy_memory(destination, source);
                }
                self.hash();
                position += space;
            }
        }


        while position < message.len() {
            let end = position + 64;
            if end <= message.len() {
                {
                    let destination = self.buffer.as_mut_slice();
                    let source = message.slice(position, end);
                    copy_memory(destination, source);
                }
                self.hash();
                position = end;
            
            // final iteration
            } else {
                {
                    let destination = self.buffer.as_mut_slice();
                    let source = message.slice_from(position);
                    copy_memory(destination, source);
                }
                self.position = message.len() - position;
                break;
            }
        } 

    }


    #[cfg(target_arch = "x86_64")]
    fn hash(chunk: &Vec<u8>, state: &Vec<u32>) {

        let mut schedule: Vec<u32> = Vec::with_capacity(64);

        unsafe {
            schedule.set_len(64);
        
        }
        let mut ptr = schedule.as_mut_ptr();
        unsafe {
            asm!(
                // Move chunk into schedule array
                "
                movq ($1), %rax
                movq 8($1), %rcx
                movq %rax, ($0)
                movq %rcx, 8($0)
                
                movq 16($1), %rax
                movq 24($1), %rcx
                movq %rax, 16($0)
                movq %rcx, 24($0)
                
                movq 32($1), %rax
                movq 40($1), %rcx
                movq %rax, 32($0)
                movq %rcx, 40($0)
                
                movq 48($1), %rax
                movq 56($1), %rcx
                movq %rax, 48($0)
                movq %rcx, 56($0)
                "    
                :"+r"(ptr)
                :"r"(chunk.as_ptr())
                : "rax", "rcx"
            );

        }
        
    }

    #[cfg(target_arch = "x86")]
    fn hash(chunk: &Vec<u8>, state: &Vec<u32>) {

        let mut schedule: Vec<u32> = Vec::with_capacity(64);

        unsafe {
            schedule.set_len(64);
        
        }
        let mut ptr = schedule.as_mut_ptr();
        unsafe {
            asm!(
                // Move chunk into schedule array
                "
                movl ($1), %eax
                movl 4($1), %ecx
                movl %eax, ($0)
                movl %ecx, 4($0)
                
                movl 8($1), %eax
                movl 12($1), %ecx
                movl %eax, 8($0)
                movl %ecx, 12($0)
                
                movl 16($1), %eax
                movl 20($1), %ecx
                movl %eax, 16($0)
                movl %ecx, 20($0)
                
                movl 24($1), %eax
                movl 28($1), %ecx
                movl %eax, 24($0)
                movl %ecx, 28($0)
                
                movl 32($1), %eax
                movl 36($1), %ecx
                movl %eax, 32($0)
                movl %ecx, 36($0)
                
                movl 40($1), %eax
                movl 44($1), %ecx
                movl %eax, 40($0)
                movl %ecx, 44($0)
                
                movl 48($1), %eax
                movl 52($1), %ecx
                movl %eax, 48($0)
                movl %ecx, 52($0)
                
                movl 56($1), %eax
                movl 60($1), %ecx
                movl %eax, 56($0)
                movl %ecx, 60($0)
                "    
                :"+r"(ptr)
                :"r"(chunk.as_ptr())
                : "eax", "ecx"
            );

        }
    }
}

#[cfg(test)]
mod test {
    #![feature(phase)]
    
    use super::Sha256;
    use std::string::String;
    
    macro_rules! rotate_right_32 (
        ($value:expr, $shift:expr) => (
            ($value >> $shift) | ($value << (32 - $shift))
        )
    )

    #[test] 
    fn test_sha256() {
        let mut hasher = Sha256::new();
        let message = String::from_str("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec ");

        hasher.update(message.as_bytes());
        
        assert!(hasher.position == 63 && message.len() == 63);
        hasher.update("a".as_bytes());
        assert!(hasher.position == 0);
    }

    #[test]
    fn test_right_rotate() {
        let five: u32 = 5;

        let shifted: u32 = 2147483650;

        assert_eq!(shifted, rotate_right_32!(five, 1));

    }
}

