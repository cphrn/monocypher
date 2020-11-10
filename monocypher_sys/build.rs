fn main() {
    cc::Build::new()
        .file("src/monocypher.c")
        .compile("monocypher");
}
