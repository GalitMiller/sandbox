# Be sure to restart your server when you modify this file.

# Your secret key for verifying the integrity of signed cookies.
# If you change this key, all old signed cookies will become invalid!
# Make sure the secret is at least 30 characters and all random,
# no regular words or you'll be exposed to dictionary attacks.
Bricata::Application.config.secret_token = ENV["BPAC_SNORBY_SECRET_TOKEN"] || "12626a7d3f25c1f4b42c2d89975086da73f4f2e4a801a0e566d1356ee2118636e71a150d9d6ce3b1c5bc572a793af838d2e3ead4b24844cee8b750eb0c4bea9f"
