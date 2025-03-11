use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Checks if the current user has root (sudo) privileges.
///
/// This function runs the `id -u` command, which returns the current user's ID.
/// In Unix-like systems, the user ID of the root user is `0`. The function checks
/// if the output of the `id -u` command is `"0"`, indicating that the user is running
/// as root (with sudo privileges).
///
/// # Returns
///
/// - `true`: If the user has root privileges (user ID is `0`).
/// - `false`: If the user does not have root privileges.
pub fn is_sudo() -> bool {
    use std::process::Command;

    // Run the "id -u" command to check the user ID
    let output = Command::new("id")
        .arg("-u")
        .output()
        .expect("Failed to execute id command");

    // Convert the output to a string and trim any whitespace
    let user_id = String::from_utf8(output.stdout).unwrap().trim().to_string();

    // Check if the user ID is 0 (which means the user is root)
    user_id == "0"
}

/// reads a vector of the form [1, 2, 3, 4] from a txt file
/// It takes the file path as a String and returns a Vec<u8>
pub fn read_vector_txt(path: String) -> io::Result<Vec<u8>> {
    // Open the file
    let mut file = File::open(path)?;

    // Read the file contents into a string
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Remove the brackets and split the string into individual numbers
    let trimmed = contents.trim_matches(|c| c == '[' || c == ']').trim();

    // Convert the split numbers into a vector of u8
    let vec: Vec<u8> = trimmed
        .split(',')
        .map(|s| s.trim().parse().expect("Failed to parse number"))
        .collect();

    // Return the vector
    Ok(vec)
}

// reads the first n bytes of a file
// useful for checking file equality
pub fn read_first_n_bytes(file_path: &str, n: usize) -> Result<Vec<u8>, anyhow::Error> {
    let mut file = File::open(file_path)?;
    let mut buffer = vec![0; n]; // Allocate a buffer of size `n`
    let bytes_read = file.read(&mut buffer)?;

    buffer.truncate(bytes_read); // Truncate buffer in case file is smaller than `n`
    Ok(buffer)
}

// Function to generate a dummy database file
pub fn generate_dummy_file(path: &Path, size: usize) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(&vec![0u8; size])?; // Fill with zero bytes
    Ok(())
}

// simulates the db file being owned by root by settong permissions to 000
pub fn restrict_file_permissions(path: &Path) -> std::io::Result<()> {
    let perms = fs::Permissions::from_mode(0o000); // owner cannot access, sudo can still bypass permissions checks
    fs::set_permissions(path, perms)
}

pub fn unrestrict_file_permissions(path: &Path) -> std::io::Result<()> {
    let perms = fs::Permissions::from_mode(0o644);
    fs::set_permissions(path, perms)
}

pub fn print_flush<S: AsRef<str>>(s: S) {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock(); // lock ensures safe writing
    write!(handle, "{}", s.as_ref()).unwrap();
    handle.flush().unwrap();
}