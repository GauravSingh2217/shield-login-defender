
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { AlertCircle, ShieldAlert, Lock, Zap } from 'lucide-react';
import { detectSqlInjection, logSqlInjectionAttempt, SqlInjectionSeverity } from '@/utils/sqlInjectionDetector';

interface LoginFormProps {
  onLoginAttempt: (username: string, password: string, isAttack: boolean, severity?: SqlInjectionSeverity) => void;
}

const LoginForm: React.FC<LoginFormProps> = ({ onLoginAttempt }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [attackDetected, setAttackDetected] = useState(false);
  const [attackPattern, setAttackPattern] = useState('');
  const [attackDescription, setAttackDescription] = useState('');
  const [attackSeverity, setAttackSeverity] = useState<SqlInjectionSeverity | undefined>(undefined);
  const [matchedText, setMatchedText] = useState('');
  const [encodingType, setEncodingType] = useState<string | undefined>(undefined);
  const [formSubmitted, setFormSubmitted] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setFormSubmitted(true);
    
    // Check for SQL injection in both username and password
    const usernameCheck = detectSqlInjection(username);
    const passwordCheck = detectSqlInjection(password);
    
    if (usernameCheck.detected || passwordCheck.detected) {
      // SQL injection detected
      const result = usernameCheck.detected ? usernameCheck : passwordCheck;
      
      setAttackDetected(true);
      setAttackPattern(result.pattern || 'Unknown pattern');
      setAttackDescription(result.description || 'Unknown attack type');
      setAttackSeverity(result.severity);
      setMatchedText(result.matchedText || '');
      setEncodingType(result.encodingType);
      
      // Log the attempt
      logSqlInjectionAttempt(
        username, 
        password, 
        result.pattern || 'Unknown pattern',
        result.description || 'Unknown attack type',
        result.severity || SqlInjectionSeverity.MEDIUM,
        result.matchedText || ''
      );
      
      // Notify parent component
      onLoginAttempt(username, password, true, result.severity);
    } else {
      // No SQL injection detected
      setAttackDetected(false);
      setAttackPattern('');
      setAttackDescription('');
      setAttackSeverity(undefined);
      setMatchedText('');
      setEncodingType(undefined);
      
      // Notify parent component
      onLoginAttempt(username, password, false);
    }
  };

  // Helper function to get alert styling based on severity
  const getSeverityClass = () => {
    switch (attackSeverity) {
      case SqlInjectionSeverity.LOW:
        return "border-yellow-400";
      case SqlInjectionSeverity.MEDIUM:
        return "border-orange-500";
      case SqlInjectionSeverity.HIGH:
        return "border-red-600 border-2";
      default:
        return "";
    }
  };

  // Helper function to get severity display text
  const getSeverityText = () => {
    switch (attackSeverity) {
      case SqlInjectionSeverity.LOW:
        return "Low Severity";
      case SqlInjectionSeverity.MEDIUM:
        return "Medium Severity";
      case SqlInjectionSeverity.HIGH:
        return "High Severity";
      default:
        return "Unknown Severity";
    }
  };

  return (
    <div className="w-full max-w-md mx-auto">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid gap-4">
          {attackDetected && (
            <Alert 
              variant="destructive" 
              className={`animate-pulse-red ${getSeverityClass()}`}
            >
              <AlertCircle className="h-4 w-4" />
              <AlertTitle className="font-bold flex items-center justify-between">
                <span>SQL Injection Detected!</span>
                {encodingType && (
                  <span className="flex items-center text-xs bg-red-100 text-red-800 px-2 py-1 rounded">
                    <Zap className="h-3 w-3 mr-1" />
                    {encodingType}
                  </span>
                )}
              </AlertTitle>
              <AlertDescription>
                <div className="space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="font-semibold">{attackDescription}</span>
                    <span className={`text-xs px-2 py-1 rounded ${attackSeverity === SqlInjectionSeverity.HIGH ? 'bg-red-600 text-white' : 
                                      attackSeverity === SqlInjectionSeverity.MEDIUM ? 'bg-orange-500 text-white' : 
                                      'bg-yellow-400 text-black'}`}>
                      {getSeverityText()}
                    </span>
                  </div>
                  <div className="text-xs mt-1 font-mono bg-alert-100 p-2 rounded text-alert-900">
                    <div>
                      <span className="font-semibold">Pattern:</span> {attackPattern}
                    </div>
                    {matchedText && (
                      <div className="mt-1">
                        <span className="font-semibold">Matched:</span> 
                        <mark className="bg-yellow-300 text-black px-1 ml-1">{matchedText}</mark>
                      </div>
                    )}
                    {encodingType && (
                      <div className="mt-1">
                        <span className="font-semibold">Encoding:</span> 
                        <span className="ml-1 text-blue-600">{encodingType}</span>
                      </div>
                    )}
                  </div>
                </div>
              </AlertDescription>
            </Alert>
          )}
          
          <div className="grid gap-2">
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              type="text"
              placeholder="Enter username or try: ' OR 1=1 --"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className={attackDetected ? "border-alert-600" : ""}
              required
            />
          </div>
          
          <div className="grid gap-2">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              placeholder="Enter password or encoded payload"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={attackDetected ? "border-alert-600" : ""}
              required
            />
          </div>
          
          <Button 
            type="submit" 
            className="w-full bg-red-600 hover:bg-red-700 text-white"
          >
            <Lock className="h-4 w-4 mr-2" />
            Test Login Security
          </Button>
        </div>
      </form>

      <div className="mt-4 p-3 bg-gray-50 rounded-lg">
        <div className="flex items-center text-xs text-gray-600 mb-2">
          <ShieldAlert className="w-3 h-3 mr-1" />
          <span>Enhanced Detection Active - Now supports encoded payloads</span>
        </div>
        <div className="text-xs text-gray-500">
          Try URL encoded (%27), Base64, or HTML entity encoded SQL injection patterns
        </div>
      </div>
    </div>
  );
};

export default LoginForm;
