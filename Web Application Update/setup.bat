@echo off
echo 🚀 Setting up Integrated Cloud Platform...
echo.

echo 📦 Installing Python dependencies...
pip install -r requirements.txt

echo.
echo ✅ Setup complete!
echo.
echo 📝 Next steps:
echo 1. Configure email_config.json with your Gmail credentials
echo 2. Run: python integrated_cloud_platform.py
echo 3. Open: http://localhost:5000
echo.
pause
