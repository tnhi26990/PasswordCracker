use hex::decode;
use pbkdf2::{pbkdf2_hmac, pbkdf2_hmac_array};
use sha2::Sha256;
use std::str;
use std::env;
use std::thread;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
const ASCII_a:u8 = 97;
const ASCII_z:u8 = 122;

//Run with: cargo test -- --nocapture --test-threads=1
//
//Can also run manually:
//Run with: cargo run -- iters salt target_hash
//
//The following command should find password "cat"
// cargo run -- 3 16 na 9f31a06f59e8310c7af9f0aa40113bcba456350e 1

fn main() {

//Get command line arguments
let args: Vec<String> = env::args().collect();

//Check we have the proper number of arguments and print a usage statement if not
//Note that the first argument is always the name of the program
if args.len() != 6 {
    println!("Usage: cargo run -- keysize iterations salt target threads");
    return;
}

//Argument 1
let keysize: usize = match args[1].parse(){
    Ok(x) => x,
    _ => {"Must enter valid integer for first argument"; return}
};

//Argument 2
let iterations: u32 = match args[2].parse(){
    Ok(x) => x,
    _ => {"Must enter valid integer for second argument"; return}
};

//Argument 3
let mut salt = args[3].clone();
salt.retain(|c| c != '\n'); //Remove the newline character from input

//Argument 4
let mut target_string = args[4].clone();
target_string.retain(|c| c != '\n'); //Remove the newline character from input
let target_vec = hex::decode(&target_string).expect("Could not decode target from hex string to hex array");
let target = &target_vec[..]; //Converts Vec<u8> to &[u8]

//Argument 5
let threads: u8 = match args[5].parse(){
    Ok(x) => x,
    _ => {"Must enter valid integer for fifth argument"; return}
};

println!("Cracking with iters: {iterations}, salt: {salt}, target: {target_string}, and threads: {threads}");

let result = crack( keysize, iterations, &salt.as_bytes(), target, threads );
if result.is_some() {
  println!("Found password: {:?}", result.unwrap());
} else {
  println!("Found password: {:?}", result);
}

}

fn generate_passwords(max_keysize: usize, iterations: u32, salt: &[u8], target: &[u8], threads: u8 ) -> Option<String> {
    let alphabet: Vec<char> = ('a'..='z').map(char::from).collect();
    let mut passwords = Vec::new();


    let mut current_password = vec!['a'; max_keysize];
    while current_password[0] <= 'z' {
       let password_str: String = current_password.iter().collect();
       passwords.push(password_str.clone());
       let mut j = max_keysize - 1;
         while j > 0 && current_password[j] == 'z' {
              current_password[j] = 'a';
              j -= 1;
          }
         if current_password[j] == 'z' {
              break;
          } else {
              let next_char = alphabet[(alphabet.iter().position(|&x| x == current_password[j]).unwrap() + 1) % 26];
              current_password[j] = next_char;
          }
     }

    let tot_pass = 26usize.pow(max_keysize as u32);
    let pass_per_thread = tot_pass / threads as usize;
    let target_arc = Arc::new(target.to_owned());
    let salt_arc = Arc::new(salt.to_owned());
    let found = Arc::new(AtomicBool::new(false));
    let mut results = Vec::new();
    let mut start = 0;
    let mut end = pass_per_thread;
    for i in 0..threads {
      if i == 0 && tot_pass % threads as usize != 0 {
         end += tot_pass % threads as usize;
      }
      if i == threads - 1 {
        end = tot_pass;
      }
      let thread_start = start;
      let thread_end = end;
      let pass = passwords.clone();
      let target_clone = Arc::clone(&target_arc);
      let salt_clone = Arc::clone(&salt_arc);
      let found_clone = Arc::clone(&found);
      let thread_handle = thread::spawn(move || {
        let mut result: Option<String> = None;
        for p in pass[thread_start..thread_end].iter() {
         let mut hash1 = [0u8; 20];
         pbkdf2_hmac::<Sha256>(p.as_bytes(), &salt_clone[..], iterations, &mut hash1);
         if hash1[..] == target_clone[..] {
            found_clone.store(true, Ordering::SeqCst);
            result = Some(p.clone());
            break;
         }
         if found_clone.load(Ordering::SeqCst) {
             break;
         }
       }
     result
   });
results.push(thread_handle);
   start = end;
   end += pass_per_thread;
  }
 for handle in results {
    let result = handle.join().unwrap();
    let password = if let Some(p) = result {
      return Some(p);
    };
  }
  None
}
//I strongly suggest you add additional functions, but please do not change the interface of
//crack()
fn crack(max_keysize: usize, iterations: u32, salt: &[u8], target: &[u8], threads: u8 ) -> Option<String> {
    let mut pass = Vec::new();
    for i in 1..=max_keysize {
      let result = generate_passwords(i, iterations, salt, &target, threads);
      if result.is_some() {
        pass.push(result.unwrap().to_string());
        break;
      }
    }
    if !pass.is_empty() {
      Some(pass[0].clone())
    } else {
      None
    }
}

#[cfg(test)]
mod password_crack_tests {

	use crate::crack;
	use hex::decode;
    use std::time::{Instant,Duration};

	#[test]
	fn call_crack() {
		let hash = hex::decode("8e95be594f2084fcad05981cac19163b54697160")
                        .expect("Could not decode target from hex string to hex array");
		crack( 2, 128, b"na", &hash, 1 );
	}

	#[test]
	fn crack_cat() {
		let hash = hex::decode("be3c153739585b98fbb96dd68be71715a311955b")
                        .expect("Could not decode target from hex string to hex array");
		let result = crack( 3, 128, b"na", &hash, 1 );
        println!("Got test result: {:?}", result );
        assert!(result.is_some());
        assert!(result.unwrap() == "cat");
	}

	#[test]
	fn crack_cat_diff_salt() {
		let hash = hex::decode("ce9b6856926fbc88af08d55d0a12571b18cc35a5")
                        .expect("Could not decode target from hex string to hex array");
		let result = crack( 3, 128, b"xy", &hash, 1 );
        assert!(result.is_some());
        assert!(result.unwrap() == "cat");
	}

    #[test]
	fn crack_dog_larger_keysize() {
		let hash = hex::decode("6bfe506d99510ddd3ed21c35f9140053e09cbf00")
                        .expect("Could not decode target from hex string to hex array");
		let result = crack( 4, 128, b"na", &hash, 1 );
        assert!(result.is_some());
        assert!(result.unwrap() == "dog");
    }

    #[test]
	fn crack_pig_two_threads() {
		let hash = hex::decode("fd1bba12fc118ff663a10796f2b45d5fdde2896b")
                        .expect("Could not decode target from hex string to hex array");
		let result = crack( 3, 128, b"na", &hash, 2 );
        assert!(result.is_some());
        assert!(result.unwrap() == "pig");
    }

    #[test]
	fn crack_mom_thread_boundary() {
		let hash = hex::decode("3228bde24088e047327b5a37f69bf536cc146c71")
                        .expect("Could not decode target from hex string to hex array");
		let result = crack( 3, 128, b"na", &hash, 2 );
        assert!(result.is_some());
        assert!(result.unwrap() == "mom");
    }

    #[test]
	fn crack_pop_thread_boundary() {
		let hash = hex::decode("c0d18be03edf3846805c16114e4ab35a67727348")
                        .expect("Could not decode target from hex string to hex array");
		let result = crack( 3, 128, b"xy", &hash, 2 );
        assert!(result.is_some());
        assert!(result.unwrap() == "pop");
    }

    #[test]
    fn test_speedup() {
        let hash = b"NoMatchingHashNoMatchingHashNoMatchingHa";

        let start = Instant::now();

        let result = crack( 3, 16, b"na", hash, 1 );
        assert!(result.is_none());
        let after_1 = Instant::now();
        let time_1 = after_1 - start;
        println!("Time on one thread: {:?}", time_1);

        let result = crack( 3, 16, b"na", hash, 2 );
        assert!(result.is_none());
        let after_2 = Instant::now();
        let time_2 = after_2 - after_1;
        println!("Time on two threads: {:?}", time_2);

        let result = crack( 3, 16, b"na", hash, 3 );
        assert!(result.is_none());
        let after_3 = Instant::now();
        let time_3 = after_3 - after_2;
        println!("Time on three threads: {:?}", time_3);

        let result = crack( 3, 16, b"na", hash, 4 );
        assert!(result.is_none());
        let after_4 = Instant::now();
        let time_4 = after_4 - after_3;
        println!("Time on four threads: {:?}", time_4);
    }
}
