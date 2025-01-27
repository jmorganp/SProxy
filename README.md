# SProxy🌐🔀

## Description

A simple Reverse Proxy implementation in Golang which proxies a http client's requests via a residential proxy
in a preferred location, whilst maintaining a proxy session for the duration of the session.

Proxy location is determined intelligently by parsing custom headers from the client or a config file.
It handles multiple concurrent sessions effortlessly and is very responsive.

Example use-case: For a Web Scraper/Crawler for bypassing geoblocks, rate-limits etc.

---

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/jmorganp/SProxy.git
   cd SProxy
   ```

2. **Install Dependencies**: Run the following command to download the required Go modules:

   ```bash
   go mod tidy
   ```

3. **Set Up Configuration**:

   - Create a `config.yaml` file in the root directory (or use the provided example `config.example.yaml`).
   - Example `config.yaml`:
     ```yaml
     user: "your-username"
     pass: "your-password"
     tgBotToken: "123456789:your-telegram-bot-token"
     telegram_chat_ids:
       - 1234567890
       - 9876543210
     ```

---

## Build

1. **Build the Project**:

   ```bash
   go build -o SProxy
   ```

   This will create an executable binary named `SProxy`.

2. **Verify the Build**: Run the binary to ensure it works as expected:

   ```bash
   ./SProxy
   ```

---

## Usage

1. **Run the Project**:

   ```bash
   ./SProxy -config=config.yaml
   ```

2. **Command-line Options**:

   - `-config` (optional): Path to the YAML configuration file. Default is `config.yaml`.

3. **Example Output**:

   ```
   Proxy server started on port 8080
   Listening for incoming requests...
   ```

---

## Features

- Proxy Management
- Secure Telegram Bot Integration (for Alerts)
- YAML Configuration Support

---

## Contributing

1. Fork the repository.
2. Create a new branch for your feature: `git checkout -b feature-name`.
3. Commit your changes: `git commit -m 'Add some feature'`.
4. Push the branch: `git push origin feature-name`.
5. Create a Pull Request.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

