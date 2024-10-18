# xss-fuzzer

# Install virtual environment package
sudo apt-get install python3-venv

Navigate to your xss-fuzzer directory
cd /path/to/xss-fuzzer

Create a Virtual Environment
python3 -m venv venv

Activate the virtual environment
source venv/bin/activate

Install required Python packages inside the virtual environment
pip install requests selenium

(If not already done) Install Google Chrome
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install ./google-chrome-stable_current_amd64.deb

Install ChromeDriver
wget https://chromedriver.storage.googleapis.com/<version>/chromedriver_linux64.zip
unzip chromedriver_linux64.zip
sudo mv chromedriver /usr/local/bin/
sudo chmod +x /usr/local/bin/chromedriver

# USAGE
Run your script inside the virtual environment
python3 xss-fuzzer.py

# Deactivate virtual environment when finished
deactivate
