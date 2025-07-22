# 🛡️ CrowdStrike Container Security Image Assessment Export Tool

## 🌟 Overview
This tool automates the process of exporting image assessment data from CrowdStrike's Container Security API. It handles pagination, authentication, and combines results into a comprehensive report.

## ✨ Features
- 🔄 Automated export job creation and management
- 🚦 Handles rate limiting and token refresh
- 📊 Supports large datasets through pagination
- 🔗 Combines multiple exports into a single report
- 💾 Outputs in both JSON and CSV formats
- 📝 Detailed logging and error handling

## 🚀 Prerequisites
- Python 3.6+
- CrowdStrike API Client ID and Secret with Container Security access
- Required Python packages:
  ```
  requests
  ```

## 📦 Installation
1. Clone the repository:
   ```bash
   git clone [repository-url]
   cd crowdstrike-container-assessment-export
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure your credentials:
   - Create a copy of `config.example.py` as `config.py`
   - Add your CrowdStrike API credentials:
     ```python
     CLIENT_ID = "your-client-id"
     CLIENT_SECRET = "your-client-secret"
     ```

## 🎮 Usage
Run the script:
```bash
python3 cs_image_assessment.py
```

The script will:
1. 🔑 Authenticate with CrowdStrike API
2. 📤 Create export jobs for each pattern (0-9, a-f)
3. 📊 Monitor job completion status
4. 📥 Download completed exports
5. 🔄 Combine results into a single report
6. 💾 Save outputs in JSON and CSV formats

## 📂 Output Files
- `combined_export_report.json`: Complete dataset in JSON format
- `combined_export_report.csv`: Complete dataset in CSV format (where possible)

## 🔄 API Flow
1. Authentication (`/oauth2/token`)
2. Export Job Creation (`/container-security/entities/exports/v1`)
3. Job Status Monitoring
4. Export Download (`/container-security/entities/exports/files/v1`)

## ⚠️ Error Handling
The script handles various error conditions:
- API rate limiting
- Token expiration
- Network issues
- Invalid responses
- Job status monitoring

## ⚙️ Configuration Options
Key parameters that can be modified in the script:
```python
self.LIMIT = 100          # Results per page
self.MAX_OFFSET = 10000   # Maximum pagination offset
max_attempts = 20         # Maximum retry attempts
```

## 📝 Logging
The script provides detailed logging including:
- Job creation status
- Export progress
- Error messages
- API responses
- Download status

## 🔧 Common Issues and Solutions
1. Rate Limiting
   - The script automatically handles rate limiting with exponential backoff
   - Adjust wait times if needed

2. Authentication Errors
   - Verify your API credentials
   - Check API access permissions
   - Ensure token refresh is working

3. Download Issues
   - Check network connectivity
   - Verify export job completion
   - Confirm API endpoint accessibility

## 🤝 Contributing
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## 📜 License
[Your chosen license]

## 👨‍💻 Author
[Your Name/Organization]

## 🙏 Acknowledgments
- CrowdStrike API Documentation
- [Other acknowledgments]

## 💬 Support
For issues and feature requests, please use the GitHub issue tracker.

## ⚠️ Disclaimer
This is not an official CrowdStrike tool. Use at your own risk and ensure compliance with CrowdStrike's API terms of service.

## 📈 Version History
- 1.0.0
  - Initial release
  - Basic export functionality
  - JSON and CSV output support

---

Made with ❤️ for the CrowdStrike Community

---

**Note**: Replace placeholder text (in brackets) with your specific information before publishing.
