
# SQL Injection Attack Detection System

## Project Overview

This web application demonstrates how SQL injection (SQLi) attacks can be detected in user input, particularly during login attempts. It uses pattern matching through regular expressions to identify common SQL injection techniques.

## What is SQL Injection?

SQL Injection is a code injection technique that exploits vulnerabilities in applications that interact with databases. By inserting malicious SQL statements into entry fields, attackers can:

- Bypass authentication
- Access, modify, or delete data without authorization
- Execute administrative operations on the database
- In some cases, issue commands to the operating system

## How This Code Detects SQL Injection

The application implements detection through:

1. **Pattern Matching**: Uses regular expressions to match user input against known SQL injection patterns
2. **Real-time Monitoring**: Checks both username and password fields during login attempts
3. **Attack Logging**: Records detected attempts with timestamp, input details, and matched pattern
4. **User Feedback**: Provides immediate visual feedback when suspicious input is detected

## Key Features

- Interactive login form that demonstrates SQL injection detection
- Educational information about SQL injection techniques and prevention
- Side-by-side examples of vulnerable vs. secure code
- Log viewer showing detected attack attempts
- Visual alerts for security events

## Getting Started

### Installation

1. Clone the repository
2. Install dependencies:
```
npm install
```

### Running the Application

```
npm run dev
```

The application will run at `localhost:8080`.

### How to Test SQL Injection Detection

Try these example inputs to see the detection in action:

- `' OR 1=1 --`
- `admin' --`
- `' UNION SELECT username, password FROM users --`
- `'; DROP TABLE users --`

## Future Improvements

- Machine learning-based detection for more sophisticated attacks
- Integration with real database to demonstrate actual prevention techniques
- More comprehensive pattern detection
- Rate limiting and IP-based blocking
- Export functionality for security logs
- User analytics to identify suspicious behavior patterns

## Educational Purpose

This application is designed for educational purposes to help understand:
- How SQL injection attacks work
- Methods for detecting and preventing such attacks
- Best practices for secure coding

## License

MIT
