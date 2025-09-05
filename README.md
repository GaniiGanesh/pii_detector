# 🔒 PII De-Identification Tool

A comprehensive web application built with Streamlit for detecting and anonymizing Personally Identifiable Information (PII) in CSV datasets. This tool provides advanced AI-powered PII detection with secure anonymization capabilities.

## ✨ Features

### 🔐 Authentication System
- **User Registration & Login**: Secure user authentication with password hashing
- **Admin Panel**: Complete administrative control with user management
- **Session Management**: Persistent login sessions with logout functionality

### 📊 PII Detection & Analysis
- **Multi-Type PII Detection**: Automatically detects various PII types:
  - **Aadhaar Numbers**: 12-digit Indian identification numbers
  - **PAN Cards**: 10-character alphanumeric tax identification
  - **Credit Card Numbers**: 13-16 digit payment card numbers
  - **Email Addresses**: Standard email format validation
  - **Phone Numbers**: 10-digit Indian mobile numbers

### 🎭 De-identification Methods
- **Anonymization**: Replaces PII with masked values (XXXX, ***)
- **Pseudo-Anonymization**: Replaces with consistent fake but realistic values

### 📈 Performance Metrics
- **True Positives (TP)**: Correctly detected PII
- **True Negatives (TN)**: Correctly ignored non-PII
- **False Positives (FP)**: Incorrectly flagged non-PII
- **False Negatives (FN)**: Missed PII
- **Precision, Recall & F1-Score**: Comprehensive performance analysis

### 📊 Data Visualization
- **Interactive Charts**: Bar charts and pie charts for metrics visualization
- **Detailed Data Views**: Clickable metrics to view specific detection results
- **Performance Scores**: Real-time calculation of accuracy metrics

### 💾 Export Capabilities
- **CSV Export**: Download de-identified data as CSV
- **Excel Export**: Download as Excel files (requires openpyxl)
- **JSON Export**: Download as JSON format
- **PDF Reports**: Generate comprehensive PDF reports with analysis

### 🛡️ Security Features
- **Data Tracking**: Complete audit trail of user activities
- **Location Logging**: IP address and location tracking for security
- **Device Detection**: Browser and device information logging
- **Admin Monitoring**: Full visibility into user activities and data processing

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Setup Instructions

1. **Clone or Download** the project files
2. **Install Dependencies**:
   ```bash
   pip install streamlit pandas matplotlib reportlab openpyxl
   ```

3. **Run the Application**:
   ```bash
   streamlit run app4.py
   ```

4. **Access the Application**:
   - Open your browser and go to `http://localhost:8501`
   

## 📖 Usage Guide

### 1. User Registration/Login
- **New Users**: Click "Sign Up" tab to create an account
- **Existing Users**: Use "Login" tab with your credentials


### 2. Data Upload
- Click "Choose a CSV file" to upload your dataset
- Supported format: CSV files only
- The system will automatically analyze the data structure

### 3. De-identification Process
- **Choose Method**: Select between Anonymization or Pseudo-Anonymization
- **Automatic Processing**: The system will scan and process all data
- **Review Results**: Examine the de-identified data and performance metrics

### 4. Performance Analysis
- **View Metrics**: Click on TP/TN/FP/FN buttons to see detailed results
- **Analyze Performance**: Review precision, recall, and F1-scores
- **Visual Charts**: Examine bar charts and pie charts for insights

### 5. Data Export
- **Download CSV**: Get the de-identified data as CSV
- **Generate Reports**: Create comprehensive PDF reports
- **Multiple Formats**: Export in CSV, Excel, or JSON formats

## 🏗️ Technical Architecture

### Core Components
- **Authentication Module**: User management and security
- **PII Detection Engine**: Pattern matching and validation
- **De-identification Engine**: Data anonymization algorithms
- **Metrics Calculator**: Performance analysis and reporting
- **Export System**: Multi-format data export capabilities

### Database Schema
- **Users Table**: User authentication and management
- **Uploaded Data**: Original data tracking and storage
- **De-identified Data**: Processed data records
- **User Locations**: Activity logging and security tracking

### Key Functions
- `detect_pii()`: Core PII detection using regex patterns
- `anonymize_pii()`: Full anonymization with masking
- `pseudo_anonymize_pii()`: Realistic fake data generation
- `is_valid_pii()`: Validation of detected PII candidates
- `generate_report()`: PDF report generation

## 🔧 Configuration

### Environment Variables
- No additional environment variables required
- Database is automatically created as `users.db`

### Customization Options
- **PII Patterns**: Modify regex patterns in `detect_pii()` function
- **Anonymization Rules**: Customize masking rules in anonymization functions
- **UI Styling**: Update CSS in the main application for custom themes

## 📊 Performance Metrics Explained

### Detection Accuracy
- **Precision**: Percentage of detected PII that are actually PII
- **Recall**: Percentage of actual PII that were correctly detected
- **F1-Score**: Harmonic mean of precision and recall

### Classification Types
- **True Positive (TP)**: Correctly identified PII
- **True Negative (TN)**: Correctly ignored non-PII
- **False Positive (FP)**: Incorrectly flagged non-PII as PII
- **False Negative (FN)**: Missed actual PII

## 🛠️ Admin Panel Features

### User Management
- View all registered users
- Delete user accounts (except admin)
- Monitor user activities

### Data Management
- View all uploaded datasets
- Access original data files
- Manage processed data records
- Bulk delete operations

### Security Monitoring
- User activity logs
- IP address tracking
- Device and browser information
- Location-based access monitoring

## 🔒 Security Considerations

### Data Protection
- All passwords are hashed using SHA-256
- Original data files are stored securely
- De-identified data maintains privacy standards

### Access Control
- Role-based access (Admin vs Regular users)
- Session management with automatic logout
- Activity logging for audit trails

### Privacy Compliance
- GDPR-compliant data handling
- Secure data anonymization
- Complete audit trails for compliance

## 🐛 Troubleshooting

### Common Issues

1. **Excel Export Not Working**
   ```bash
   pip install openpyxl
   ```

2. **Database Errors**
   - Delete `users.db` file to reset the database
   - Restart the application

3. **Port Already in Use**
   ```bash
   streamlit run app4.py --server.port 8502
   ```

### Performance Optimization
- For large datasets (>10,000 rows), processing may take longer
- Consider chunking large files for better performance
- Monitor memory usage with very large datasets

## 📝 License

This project is developed for educational and research purposes. Please ensure compliance with local data protection regulations when using this tool.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

For technical support or questions:
- Check the troubleshooting section
- Review the code comments for implementation details
- Ensure all dependencies are properly installed

## 🔄 Version History

- **v1.0**: Initial release with basic PII detection
- **v2.0**: Added authentication and admin panel
- **v3.0**: Enhanced metrics and visualization
- **v4.0**: Current version with comprehensive features

---

**⚠️ Important Note**: This tool is designed for legitimate data anonymization purposes. Always ensure you have proper authorization before processing any sensitive data and comply with applicable data protection laws and regulations.
