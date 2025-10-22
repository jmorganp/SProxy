# SProxy🌐🔀

## Description

A simple reverse proxy implementation in Golang that tunnels HTTP client requests through residential proxies in a specified locations, while maintaining a persistent session for the specified duration.

The proxy location is smartly determined by by analyzing incoming requests. It efficiently handles multiple concurrent sessions and is highly responsive.

Example use case: A web scraper or crawler for bypassing geo-restrictions, rate limits etc.

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
     proxy-user: "your-username"
     proxy-pass: "your-password"
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

