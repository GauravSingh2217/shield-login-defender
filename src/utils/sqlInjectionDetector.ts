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
  /#.*/,                           // # comment (MySQL)
  
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
  /CHAR\(\d+\)/i,                       // CHAR() function
  
  // Additional patterns for more thorough detection
  /ORDER\s+BY\s+\d+/i,                  // ORDER BY injection
  /GROUP\s+BY\s+\d+/i,                  // GROUP BY injection
  /HAVING\s+\d+/i,                      // HAVING injection
  /LOAD_FILE\s*\(/i,                    // File reading attempts
  /INTO\s+(OUT|DUMP)FILE/i,             // File writing attempts
  /CAST\s*\(/i,                         // CAST function used in attacks
  /CONVERT\s*\(/i,                      // CONVERT function
  /CONCAT\s*\(/i,                       // String concatenation used in attacks
  /CONCAT_WS\s*\(/i,                    // String concatenation with separator
  /@@VERSION/i,                         // Database version query
  /@@HOSTNAME/i,                        // Hostname query
  /@@datadir/i,                         // Data directory query
  
  // MS-SQL specific
  /sp_password/i,                       // MS SQL stored procedure
  /xp_cmdshell/i,                       // MS SQL command execution
  
  // Oracle specific 
  /DBMS_/i,                             // Oracle DBMS packages
  /UTL_/i,                              // Oracle UTL packages
  
  // MySQL specific
  /information_schema\.(tables|columns)/i, // Information schema access
  /mysql\.(user|host|db)/i,             // MySQL internal tables
  
  // PostgreSQL specific
  /pg_catalog\.(pg_tables|pg_class)/i,  // PostgreSQL catalog tables
  /pg_sleep\s*\(/i,                     // PostgreSQL sleep function
  
  // SQLite specific
  /sqlite_master/i,                     // SQLite schema table
  
  // Time-based attack patterns
  /BENCHMARK\s*\(/i,                    // MySQL benchmark
  /PG_SLEEP\s*\(/i,                     // PostgreSQL sleep
  /WAITFOR\s+DELAY/i,                   // MS SQL delay
  
  // Boolean-based blind patterns
  /AND\s+(SELECT|1)\s*=\s*(SELECT|1)/i, // AND boolean
  /OR\s+(SELECT|1)\s*=\s*(SELECT|1)/i,  // OR boolean
  
  // Error-based patterns
  /AND\s+EXTRACTVALUE\s*\(/i,           // MySQL error-based
  /AND\s+UPDATEXML\s*\(/i,              // MySQL error-based
  /AND\s+EXP\s*\(/i,                    // Oracle error-based
  
  // Second-order patterns
  /SELECT.+FROM.+WHERE.+IN\s*\(\s*SELECT/i, // Subselect
  
  // Special characters often used in SQLi
  /'\s*;\s*--/,                         // Closing quote with comment
  /'\s*;\s*#/,                          // Closing quote with MySQL comment
  
  // Evasion techniques
  /\/\*!.*\*\//,                        // MySQL version comment
  /UNHEX\s*\(/i,                        // Hex decoding
  /BASE64\s*\(/i,                       // Base64 encoding/decoding
  /FROM_BASE64\s*\(/i,                  // Base64 decoding
  
  // Unicode evasion
  /U\+[0-9A-F]{4}/i,                    // Unicode character reference
  
  // Case variance
  /(?:s|%73)(?:e|%65)(?:l|%6C)(?:e|%65)(?:c|%63)(?:t|%74)/i, // SELECT with case/encoding variance
  /(?:u|%75)(?:n|%6E)(?:i|%69)(?:o|%6F)(?:n|%6E)/i,          // UNION with case/encoding variance
  
  // Multi-context patterns
  /'\s+AND\s+\d+\s*=\s*\d+\s+--/i,      // Quote AND condition comment
  /'\s+OR\s+\d+\s*=\s*\d+\s+--/i,       // Quote OR condition comment
  
  // Whitespace manipulation
  /'\s+OR\s+'\w+'\s*=\s*'\w+'/i,        // OR with excessive whitespace
  /'\s+AND\s+'\w+'\s*=\s*'\w+'/i,       // AND with excessive whitespace
  
  // More sophisticated patterns
  /CASE\s+WHEN\s+.*\s+THEN\s+.*\s+ELSE\s+.*\s+END/i, // CASE expressions
  /IIF\s*\(/i,                          // IIF conditional function
  /LIKE\s+BINARY\s+/i,                  // LIKE BINARY comparison
  /SELECT\s+@@/i,                       // System variable access
  
  // Common boolean blind SQLi
  /'\s+AND\s+\d+=\d+\s+--/i,            // AND boolean with comment
  /'\s+AND\s+\d+=\d+\s+#/i              // AND boolean with MySQL comment
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
