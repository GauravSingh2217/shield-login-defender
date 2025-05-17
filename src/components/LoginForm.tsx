
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { AlertCircle, ShieldAlert, Lock } from 'lucide-react';
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
    <Card className="w-full max-w-md shadow-lg border-security-300">
      <CardHeader className="space-y-1 bg-security-700 text-white rounded-t-lg">
        <div className="flex items-center justify-center mb-2">
          <Lock className="h-8 w-8 text-security-200" />
        </div>
        <CardTitle className="text-2xl text-center">Login</CardTitle>
        <CardDescription className="text-security-100 text-center">
          Try entering SQL injection patterns to see detection in action
        </CardDescription>
      </CardHeader>
      <CardContent className="pt-6">
        <form onSubmit={handleSubmit}>
          <div className="grid gap-4">
            {attackDetected && (
              <Alert 
                variant="destructive" 
                className={`animate-pulse-red ${getSeverityClass()}`}
              >
                <AlertCircle className="h-4 w-4" />
                <AlertTitle className="font-bold">SQL Injection Detected!</AlertTitle>
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
                    <div className="text-xs mt-1 font-mono bg-alert-100 p-1 rounded text-alert-900">
                      <div>
                        <span className="font-semibold">Pattern:</span> {attackPattern}
                      </div>
                      {matchedText && (
                        <div className="mt-1">
                          <span className="font-semibold">Matched:</span> <mark className="bg-yellow-300 text-black px-1">{matchedText}</mark>
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
                placeholder="Enter username"
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
                placeholder="Enter password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={attackDetected ? "border-alert-600" : ""}
                required
              />
            </div>
            
            <Button 
              type="submit" 
              className="w-full bg-security-600 hover:bg-security-700"
            >
              Sign In
            </Button>
          </div>
        </form>
      </CardContent>
      <CardFooter className="flex-col text-sm text-muted-foreground">
        <div className="flex items-center justify-center text-xs">
          <ShieldAlert className="w-3 h-3 mr-1" />
          <span>This is for educational purposes only</span>
        </div>
      </CardFooter>
    </Card>
  );
};

export default LoginForm;
