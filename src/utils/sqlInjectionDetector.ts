/**
 * SQL Injection Detection Utility
 * 
 * This module provides functions for detecting potential SQL injection attacks
 * in user input by matching against common SQL injection patterns including encoded payloads.
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

// Define common SQL injection patterns with severity levels including encoded payloads
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
  
  // URL Encoded SQL Injection Patterns
  {
    pattern: /%27.*%4F%52.*%3D/i,
    description: 'URL encoded OR condition attack (%27 OR %3D)',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /%27.*%4F%52.*1%3D1/i,
    description: 'URL encoded OR 1=1 attack',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /%2527.*%254F%2552.*%253D/i,
    description: 'Double URL encoded OR attack',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /%27.*%55%4E%49%4F%4E.*%53%45%4C%45%43%54/i,
    description: 'URL encoded UNION SELECT attack',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // HTML Entity Encoded Attacks
  {
    pattern: /&#x27;.*&#x4F;&#x52;.*&#x3D;/i,
    description: 'HTML hex encoded OR attack',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /&#39;.*&#79;&#82;.*&#61;/i,
    description: 'HTML decimal encoded OR attack',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /&apos;.*OR.*&equals;/i,
    description: 'HTML named entity encoded attack',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Base64 Encoded Patterns
  {
    pattern: /J08gMT0x/i, // Base64 for " OR 1=1"
    description: 'Base64 encoded OR 1=1 attack',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /Jy4qT1IuKjE9MQ==/i, // Base64 for "'.*OR.*1=1"
    description: 'Base64 encoded OR condition',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /VU5JT04gU0VMRUNUA==/i, // Base64 for "UNION SELECT"
    description: 'Base64 encoded UNION SELECT',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Hex Encoded Patterns
  {
    pattern: /0x[0-9a-f]*27[0-9a-f]*4f[0-9a-f]*52[0-9a-f]*/i,
    description: 'Hex encoded SQL injection with quotes and OR',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /0x[0-9a-f]*55[0-9a-f]*4e[0-9a-f]*49[0-9a-f]*4f[0-9a-f]*4e[0-9a-f]*/i,
    description: 'Hex encoded UNION attack',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Unicode Encoded Attacks
  {
    pattern: /\\u0027.*\\u004F\\u0052.*\\u003D/i,
    description: 'Unicode encoded OR attack',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /\\u0055\\u004E\\u0049\\u004F\\u004E/i,
    description: 'Unicode encoded UNION',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Comment attacks
  {
    pattern: /--.*$/,
    description: 'SQL comment attack',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /%2D%2D/i,
    description: 'URL encoded comment attack (--)',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /\/\*.*\*\//,
    description: 'Multi-line comment attack',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /%2F%2A.*%2A%2F/i,
    description: 'URL encoded multi-line comment',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /#.*/,
    description: 'MySQL comment attack',
    severity: SqlInjectionSeverity.MEDIUM
  },
  {
    pattern: /%23/i,
    description: 'URL encoded MySQL comment (#)',
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
  
  // Additional encoded patterns for common SQLi payloads
  {
    pattern: /%53%45%4C%45%43%54/i,
    description: 'URL encoded SELECT statement',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /%49%4E%53%45%52%54/i,
    description: 'URL encoded INSERT statement',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /%44%45%4C%45%54%45/i,
    description: 'URL encoded DELETE statement',
    severity: SqlInjectionSeverity.HIGH
  },
  {
    pattern: /%55%50%44%41%54%45/i,
    description: 'URL encoded UPDATE statement',
    severity: SqlInjectionSeverity.HIGH
  },
  
  // Keep existing patterns...
  // ... keep existing code (all other SQL injection patterns)
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
  encodingType?: string;
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
  encodingType?: string;
}

/**
 * Helper function to detect encoding type
 */
function detectEncodingType(input: string): string | undefined {
  if (/%[0-9A-F]{2}/i.test(input)) return 'URL Encoded';
  if (/&#x[0-9A-F]+;/i.test(input)) return 'HTML Hex Entity';
  if (/&#\d+;/.test(input)) return 'HTML Decimal Entity';
  if (/\\u[0-9A-F]{4}/i.test(input)) return 'Unicode Escaped';
  if (/0x[0-9A-F]+/i.test(input)) return 'Hexadecimal';
  if (/^[A-Za-z0-9+/]*={0,2}$/.test(input) && input.length % 4 === 0 && input.length > 8) return 'Base64';
  return undefined;
}

/**
 * Detects potential SQL injection patterns in a string including encoded payloads
 * 
 * @param input - The user input string to check
 * @returns Object with detection result and additional information if found
 */
export function detectSqlInjection(input: string): SqlInjectionResult {
  // Skip detection for empty strings
  if (!input || input.trim() === '') {
    return { detected: false };
  }

  // Detect encoding type
  const encodingType = detectEncodingType(input);

  // Try to decode common encodings for better detection
  let decodedInputs = [input];
  
  try {
    // URL decode
    if (input.includes('%')) {
      decodedInputs.push(decodeURIComponent(input));
    }
    
    // HTML entity decode (basic)
    let htmlDecoded = input
      .replace(/&#x([0-9A-F]+);/gi, (match, hex) => String.fromCharCode(parseInt(hex, 16)))
      .replace(/&#(\d+);/g, (match, dec) => String.fromCharCode(parseInt(dec, 10)))
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&');
    decodedInputs.push(htmlDecoded);
    
    // Base64 decode (if it looks like base64)
    if (/^[A-Za-z0-9+/]*={0,2}$/.test(input) && input.length % 4 === 0 && input.length > 8) {
      try {
        decodedInputs.push(atob(input));
      } catch (e) {
        // Not valid base64, ignore
      }
    }
  } catch (e) {
    // Decoding failed, continue with original input
  }

  // Check all inputs (original and decoded) against patterns
  for (const testInput of decodedInputs) {
    for (const patternObj of SQL_INJECTION_PATTERNS) {
      const match = testInput.match(patternObj.pattern);
      if (match) {
        return { 
          detected: true,
          pattern: patternObj.pattern.toString().replace(/\/(.*)\/[gi]?/, '$1'),
          description: patternObj.description,
          severity: patternObj.severity,
          matchedText: match[0],
          encodingType
        };
      }
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
