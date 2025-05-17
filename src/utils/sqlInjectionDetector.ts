/**
 * SQL Injection Detection Utility
 * 
 * This module provides functions for detecting potential SQL injection attacks
 * in user input by matching against common SQL injection patterns.
 */

// Define common SQL injection patterns as regular expressions
const SQL_INJECTION_PATTERNS = [
  // Basic SQL injection attacks
  /'.*OR.*['=]/i,                  // 'OR 1=1--
  /'.*OR.*1.*?=.*?1.*/i,           // ' OR 1=1
  /'.*OR.*TRUE.*/i,                // ' OR TRUE
  /'.*(AND|OR).*['=]/i,            // ' AND 1=1
  
  // Comment attacks
  /--.*$/,                         // -- comment
  /\/\*.*\*\//,                    // /* comment */
  
  // UNION-based attacks
  /UNION.*SELECT/i,                // UNION SELECT
  /UNION.*ALL.*SELECT/i,           // UNION ALL SELECT
  
  // Other SQL commands
  /INSERT.*INTO/i,                 // INSERT INTO
  /UPDATE.*SET/i,                  // UPDATE SET
  /DELETE.*FROM/i,                 // DELETE FROM
  /DROP.*TABLE/i,                  // DROP TABLE
  /ALTER.*TABLE/i,                 // ALTER TABLE
  /EXEC.*sp_/i,                    // EXEC sp_
  /EXEC.*xp_/i,                    // EXEC xp_
  
  // Batched queries
  /;.*SELECT/i,                    // ;SELECT
  /;.*INSERT/i,                    // ;INSERT
  /;.*UPDATE/i,                    // ;UPDATE
  /;.*DELETE/i,                    // ;DELETE
  /;.*DROP/i,                      // ;DROP
  
  // Common SQLi test strings
  /SELECT.*FROM.*information_schema/i,  // information_schema tables
  /SELECT.*FROM.*sysobjects/i,          // sysobjects
  /SLEEP\(\d+\)/i,                      // SLEEP() function
  /BENCHMARK\(\d+,.*\)/i,               // BENCHMARK() function
  /WAITFOR.*DELAY/i,                    // WAITFOR DELAY
  
  // Hex/char encoding
  /0x[0-9a-f]{2,}/i,                    // Hex-encoded strings
  /CHAR\(\d+\)/i                        // CHAR() function
];

/**
 * Detects potential SQL injection patterns in a string
 * 
 * @param input - The user input string to check
 * @returns Object with detection result and matched pattern if found
 */
export function detectSqlInjection(input: string): { detected: boolean; pattern?: string } {
  // Skip detection for empty strings
  if (!input || input.trim() === '') {
    return { detected: false };
  }

  for (const pattern of SQL_INJECTION_PATTERNS) {
    if (pattern.test(input)) {
      return { 
        detected: true,
        pattern: pattern.toString().replace(/\/(.*)\/[gi]?/, '$1') // Convert regex to string for logging
      };
    }
  }

  return { detected: false };
}

/**
 * Logs a detected SQL injection attempt
 * 
 * @param username - The username input
 * @param password - The password input that triggered detection
 * @param pattern - The pattern that was matched
 * @returns The log entry as a string
 */
export function logSqlInjectionAttempt(
  username: string,
  password: string,
  pattern: string
): string {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    username: username || '(empty)',
    password: password || '(empty)',
    pattern
  };
  
  console.warn('SQL INJECTION ATTEMPT DETECTED:', logEntry);
  
  // Create log entry string
  const logString = JSON.stringify(logEntry);
  
  // In a real application, this would write to a file or database
  // For this demo, we just store in localStorage for demonstration purposes
  const existingLogs = localStorage.getItem('sql_injection_logs') || '[]';
  const logsArray = JSON.parse(existingLogs);
  logsArray.push(logEntry);
  localStorage.setItem('sql_injection_logs', JSON.stringify(logsArray));
  
  return logString;
}

/**
 * Gets all logged SQL injection attempts
 * 
 * @returns Array of log entries
 */
export function getSqlInjectionLogs(): any[] {
  const logs = localStorage.getItem('sql_injection_logs') || '[]';
  return JSON.parse(logs);
}

/**
 * Clears all logged SQL injection attempts
 */
export function clearSqlInjectionLogs(): void {
  localStorage.removeItem('sql_injection_logs');
}
