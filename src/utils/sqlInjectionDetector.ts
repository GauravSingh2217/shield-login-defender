/**
 * SQL Injection Detection Utility
 * 
 * This module provides functions for detecting potential SQL injection attacks
 * in user input by matching against common SQL injection patterns.
 */

// Pattern severity levels
export enum SqlInjectionSeverity {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high"
}

// Interface for pattern definitions
interface SqlInjectionPattern {
  pattern: RegExp;
  description: string;
  severity: SqlInjectionSeverity;
}

// Define common SQL injection patterns with severity levels
const SQL_INJECTION_PATTERNS: SqlInjectionPattern[] = [
  // Basic SQL injection attacks
  {
    pattern: /'.*OR.*['=]/i,
    description: 'Basic OR condition attack',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /'.*OR.*1.*?=.*?1.*/i,
    description: 'OR 1=1 condition attack',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /'.*OR.*TRUE.*/i,
    description: 'OR TRUE condition attack',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /'.*(AND|OR).*['=]/i,
    description: 'AND/OR condition attack',
    severity: SqlInjectionSeverity.MEDIUM
  },
  
  // Comment attacks
  {
    pattern: /--.*$/,
    description: 'SQL comment attack',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /\/\*.*\*\//,
    description: 'Multi-line comment attack',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /#.*/,
    description: 'MySQL comment attack',
    severity: SqlInjectionSeverity.MEDIUM
  },
  
  // UNION-based attacks
  {
    pattern: /UNION.*SELECT/i,
    description: 'UNION-based attack',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /UNION.*ALL.*SELECT/i,
    description: 'UNION ALL-based attack',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Other SQL commands
  {
    pattern: /INSERT.*INTO/i,
    description: 'INSERT command',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /UPDATE.*SET/i,
    description: 'UPDATE command',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /DELETE.*FROM/i,
    description: 'DELETE command',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /DROP.*TABLE/i,
    description: 'DROP TABLE command',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /ALTER.*TABLE/i,
    description: 'ALTER TABLE command',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /EXEC.*sp_/i,
    description: 'Stored procedure execution',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /EXEC.*xp_/i,
    description: 'Extended procedure execution',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Batched queries
  {
    pattern: /;.*SELECT/i,
    description: 'Batched SELECT query',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /;.*INSERT/i,
    description: 'Batched INSERT query',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /;.*UPDATE/i,
    description: 'Batched UPDATE query',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /;.*DELETE/i,
    description: 'Batched DELETE query',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /;.*DROP/i,
    description: 'Batched DROP query',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Common SQLi test strings
  {
    pattern: /SELECT.*FROM.*information_schema/i,
    description: 'Information schema query',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /SELECT.*FROM.*sysobjects/i,
    description: 'System objects query',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /SLEEP\(\d+\)/i,
    description: 'Time-based attack (SLEEP)',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /BENCHMARK\(\d+,.*\)/i,
    description: 'Time-based attack (BENCHMARK)',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /WAITFOR.*DELAY/i,
    description: 'Time-based attack (WAITFOR DELAY)',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Hex/char encoding
  {
    pattern: /0x[0-9a-f]{2,}/i,
    description: 'Hex-encoded string',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /CHAR\(\d+\)/i,
    description: 'CHAR function',
    severity: SqlInjectionSeverity.MEDIUM
  },
  
  // Additional patterns for more thorough detection
  {
    pattern: /ORDER\s+BY\s+\d+/i,
    description: 'ORDER BY injection',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /GROUP\s+BY\s+\d+/i,
    description: 'GROUP BY injection',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /HAVING\s+\d+/i,
    description: 'HAVING injection',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /LOAD_FILE\s*\(/i,
    description: 'File reading attempt',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /INTO\s+(OUT|DUMP)FILE/i,
    description: 'File writing attempt',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /CAST\s*\(/i,
    description: 'CAST function',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /CONVERT\s*\(/i,
    description: 'CONVERT function',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /CONCAT\s*\(/i,
    description: 'String concatenation',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /CONCAT_WS\s*\(/i,
    description: 'String concatenation with separator',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /@@VERSION/i,
    description: 'Database version query',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /@@HOSTNAME/i,
    description: 'Hostname query',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /@@datadir/i,
    description: 'Data directory query',
    severity: SqlInjectionSeverity.MEDIUM
  },
  
  // MS-SQL specific
  {
    pattern: /sp_password/i,
    description: 'MS SQL stored procedure',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /xp_cmdshell/i,
    description: 'MS SQL command execution',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Oracle specific 
  {
    pattern: /DBMS_/i,
    description: 'Oracle DBMS packages',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /UTL_/i,
    description: 'Oracle UTL packages',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // MySQL specific
  {
    pattern: /information_schema\.(tables|columns)/i,
    description: 'MySQL information schema access',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /mysql\.(user|host|db)/i,
    description: 'MySQL internal tables access',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // PostgreSQL specific
  {
    pattern: /pg_catalog\.(pg_tables|pg_class)/i,
    description: 'PostgreSQL catalog tables',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /pg_sleep\s*\(/i,
    description: 'PostgreSQL sleep function',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // SQLite specific
  {
    pattern: /sqlite_master/i,
    description: 'SQLite schema table',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Time-based attack patterns
  {
    pattern: /BENCHMARK\s*\(/i,
    description: 'MySQL benchmark',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /PG_SLEEP\s*\(/i,
    description: 'PostgreSQL sleep',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /WAITFOR\s+DELAY/i,
    description: 'MS SQL delay',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Boolean-based blind patterns
  {
    pattern: /AND\s+(SELECT|1)\s*=\s*(SELECT|1)/i,
    description: 'AND boolean',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /OR\s+(SELECT|1)\s*=\s*(SELECT|1)/i,
    description: 'OR boolean',
    severity: SqlInjectionSeverity.MEDIUM
  },
  
  // Error-based patterns
  {
    pattern: /AND\s+EXTRACTVALUE\s*\(/i,
    description: 'MySQL error-based attack',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /AND\s+UPDATEXML\s*\(/i,
    description: 'MySQL error-based attack',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /AND\s+EXP\s*\(/i,
    description: 'Oracle error-based attack',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Second-order patterns
  {
    pattern: /SELECT.+FROM.+WHERE.+IN\s*\(\s*SELECT/i,
    description: 'Subselect query',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Special characters often used in SQLi
  {
    pattern: /'\s*;\s*--/,
    description: 'Closing quote with comment',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /'\s*;\s*#/,
    description: 'Closing quote with MySQL comment',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Evasion techniques
  {
    pattern: /\/\*!.*\*\//,
    description: 'MySQL version comment',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /UNHEX\s*\(/i,
    description: 'Hex decoding',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /BASE64\s*\(/i,
    description: 'Base64 encoding/decoding',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /FROM_BASE64\s*\(/i,
    description: 'Base64 decoding',
    severity: SqlInjectionSeverity.MEDIUM
  },
  
  // Unicode evasion
  {
    pattern: /U\+[0-9A-F]{4}/i,
    description: 'Unicode character reference',
    severity: SqlInjectionSeverity.MEDIUM
  },
  
  // Case variance
  {
    pattern: /(?:s|%73)(?:e|%65)(?:l|%6C)(?:e|%65)(?:c|%63)(?:t|%74)/i,
    description: 'SELECT with case/encoding variance',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /(?:u|%75)(?:n|%6E)(?:i|%69)(?:o|%6F)(?:n|%6E)/i,
    description: 'UNION with case/encoding variance',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Multi-context patterns
  {
    pattern: /'\s+AND\s+\d+\s*=\s*\d+\s+--/i,
    description: 'Quote AND condition comment',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /'\s+OR\s+\d+\s*=\s*\d+\s+--/i,
    description: 'Quote OR condition comment',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Whitespace manipulation
  {
    pattern: /'\s+OR\s+'\w+'\s*=\s*'\w+'/i,
    description: 'OR with excessive whitespace',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /'\s+AND\s+'\w+'\s*=\s*'\w+'/i,
    description: 'AND with excessive whitespace',
    severity: SqlInjectionSeverity.MEDIUM
  },
  
  // More sophisticated patterns
  {
    pattern: /CASE\s+WHEN\s+.*\s+THEN\s+.*\s+ELSE\s+.*\s+END/i,
    description: 'CASE expression',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /IIF\s*\(/i,
    description: 'IIF conditional function',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /LIKE\s+BINARY\s+/i,
    description: 'LIKE BINARY comparison',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /SELECT\s+@@/i,
    description: 'System variable access',
    severity: SqlInjectionSeverity.MEDIUM
  },
  
  // Common boolean blind SQLi
  {
    pattern: /'\s+AND\s+\d+=\d+\s+--/i,
    description: 'AND boolean with comment',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /'\s+AND\s+\d+=\d+\s+#/i,
    description: 'AND boolean with MySQL comment',
    severity: SqlInjectionSeverity.HIGH
  }
];

/**
 * Detection result interface
 */
export interface SqlInjectionResult {
  detected: boolean;
  pattern?: string;
  description?: string;
  severity?: SqlInjectionSeverity;
  matchedText?: string;
}

/**
 * Log entry interface
 */
export interface SqlInjectionLogEntry {
  timestamp: string;
  username: string;
  password: string;
  pattern: string;
  description: string;
  severity: SqlInjectionSeverity;
  matchedText: string;
}

/**
 * Detects potential SQL injection patterns in a string
 * 
 * @param input - The user input string to check
 * @returns Object with detection result and additional information if found
 */
export function detectSqlInjection(input: string): SqlInjectionResult {
  // Skip detection for empty strings
  if (!input || input.trim() === '') {
    return { detected: false };
  }

  for (const patternObj of SQL_INJECTION_PATTERNS) {
    const match = input.match(patternObj.pattern);
    if (match) {
      return { 
        detected: true,
        pattern: patternObj.pattern.toString().replace(/\/(.*)\/[gi]?/, '$1'),
        description: patternObj.description,
        severity: patternObj.severity,
        matchedText: match[0]
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
 * @param description - Description of the pattern
 * @param severity - Severity level of the detected pattern
 * @param matchedText - The text that matched the pattern
 * @returns The log entry as a string
 */
export function logSqlInjectionAttempt(
  username: string,
  password: string,
  pattern: string,
  description: string,
  severity: SqlInjectionSeverity,
  matchedText: string
): string {
  const timestamp = new Date().toISOString();
  const logEntry: SqlInjectionLogEntry = {
    timestamp,
    username: username || '(empty)',
    password: password || '(empty)',
    pattern,
    description,
    severity,
    matchedText
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
export function getSqlInjectionLogs(): SqlInjectionLogEntry[] {
  const logs = localStorage.getItem('sql_injection_logs') || '[]';
  return JSON.parse(logs);
}

/**
 * Clears all logged SQL injection attempts
 */
export function clearSqlInjectionLogs(): void {
  localStorage.removeItem('sql_injection_logs');
}

/**
 * Export logs as JSON file
 */
export function exportSqlInjectionLogs(): void {
  const logs = getSqlInjectionLogs();
  
  if (logs.length === 0) {
    console.warn('No logs to export');
    return;
  }
  
  const dataStr = JSON.stringify(logs, null, 2);
  const dataUri = `data:application/json;charset=utf-8,${encodeURIComponent(dataStr)}`;
  
  const exportFileName = `sql_injection_logs_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
  
  const linkElement = document.createElement('a');
  linkElement.setAttribute('href', dataUri);
  linkElement.setAttribute('download', exportFileName);
  linkElement.style.display = 'none';
  
  document.body.appendChild(linkElement);
  linkElement.click();
  document.body.removeChild(linkElement);
}

/**
 * Filter logs based on criteria
 * 
 * @param logs - The logs to filter
 * @param filters - Object containing filter criteria
 * @returns Filtered array of logs
 */
export function filterSqlInjectionLogs(
  logs: SqlInjectionLogEntry[],
  filters: {
    severity?: SqlInjectionSeverity,
    search?: string,
    fromDate?: string,
    toDate?: string
  }
): SqlInjectionLogEntry[] {
  return logs.filter(log => {
    // Filter by severity if specified
    if (filters.severity && log.severity !== filters.severity) {
      return false;
    }
    
    // Filter by search term if specified
    if (filters.search) {
      const searchTerm = filters.search.toLowerCase();
      const searchableFields = [
        log.username,
        log.password,
        log.pattern,
        log.description,
        log.matchedText
      ];
      
      if (!searchableFields.some(field => field.toLowerCase().includes(searchTerm))) {
        return false;
      }
    }
    
    // Filter by date range if specified
    if (filters.fromDate) {
      const fromDate = new Date(filters.fromDate);
      const logDate = new Date(log.timestamp);
      if (logDate < fromDate) {
        return false;
      }
    }
    
    if (filters.toDate) {
      const toDate = new Date(filters.toDate);
      const logDate = new Date(log.timestamp);
      if (logDate > toDate) {
        return false;
      }
    }
    
    return true;
  });
}

/**
 * Counts logs by severity
 * 
 * @returns Object with counts by severity level
 */
export function countLogsBySeverity(logs: SqlInjectionLogEntry[]): Record<SqlInjectionSeverity, number> {
  const counts = {
    [SqlInjectionSeverity.LOW]: 0,
    [SqlInjectionSeverity.MEDIUM]: 0,
    [SqlInjectionSeverity.HIGH]: 0
  };
  
  logs.forEach(log => {
    counts[log.severity]++;
  });
  
  return counts;
}
