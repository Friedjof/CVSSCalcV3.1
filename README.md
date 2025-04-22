# CVSS v3.1 Calculator 💻🎯

Welcome to the **CVSS v3.1 Calculator**! This project provides an intuitive UI for calculating CVSS v3.1 base scores and generating corresponding vectors. It's designed to help you assess vulnerabilities with ease. 🚀

## Features ✨
- Interactive UI for CVSS v3.1 base metric selection.
- Real-time score calculation and vector generation.
- Dockerized setup for easy deployment. 🐳
- Clean and responsive design.

![CVSS v3.1 Calculator Screenshot](/media/preview-01.png)

## Getting Started 🛠️

### Prerequisites
- Docker and Docker Compose installed on your system.

### Setup with Docker 🐳

#### GitHub Registry

1. Pull the Docker image from GitHub Container Registry:
   ```bash
   docker pull ghcr.io/friedjof/cvsscalcv3.1:latest
   ```

2. Start the Docker container:
   ```bash
   docker run -d -p 80:8080 ghcr.io/friedjof/cvsscalcv3.1:latest
   ```

3. Open your browser and navigate to:
   ```
   http://localhost
   ```

#### Local
1. Clone this repository:
   ```bash
   git clone https://github.com/Friedjof/CVSSCalcV3.1.git
   cd CVSSCalcV3.1
   ```

2. Build and start the application:
   ```bash
   docker compose up --build
   ```

3. Open your browser and navigate to:
   ```
   http://localhost
   ```

That's it! Your CVSS Calculator is now running. 🎉

### Development Setup 🔧
If you want to run the application locally without Docker, you can do so by following these steps:

1. Create a virtual environment:
   ```bash
   python -m venv venv
   ```

2. Activate the virtual environment:
    - On Windows:
      ```bash
      venv\Scripts\activate
      ```
    - On macOS/Linux:
      ```bash
      source venv/bin/activate
      ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python main.py
   ```

## Project Structure 📂
- `main.py`: Core application logic.
- `static/styles.css`: Custom styles for the UI.
- `Dockerfile`: Docker image setup.
- `compose.yml`: Docker Compose configuration.

## Contributing 🤝
Feel free to fork this repository, submit issues, or create pull requests. Contributions are always welcome! 🌟
