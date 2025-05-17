
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { AlertCircle, ShieldAlert, Lock } from 'lucide-react';
import { detectSqlInjection, logSqlInjectionAttempt } from '@/utils/sqlInjectionDetector';

interface LoginFormProps {
  onLoginAttempt: (username: string, password: string, isAttack: boolean) => void;
}

const LoginForm: React.FC<LoginFormProps> = ({ onLoginAttempt }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [attackDetected, setAttackDetected] = useState(false);
  const [attackPattern, setAttackPattern] = useState('');
  const [formSubmitted, setFormSubmitted] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setFormSubmitted(true);
    
    // Check for SQL injection in both username and password
    const usernameCheck = detectSqlInjection(username);
    const passwordCheck = detectSqlInjection(password);
    
    if (usernameCheck.detected || passwordCheck.detected) {
      // SQL injection detected
      const detectedPattern = usernameCheck.detected 
        ? usernameCheck.pattern 
        : passwordCheck.pattern;
        
      setAttackDetected(true);
      setAttackPattern(detectedPattern || 'Unknown pattern');
      
      // Log the attempt
      logSqlInjectionAttempt(username, password, detectedPattern || 'Unknown pattern');
      
      // Notify parent component
      onLoginAttempt(username, password, true);
    } else {
      // No SQL injection detected
      setAttackDetected(false);
      setAttackPattern('');
      
      // Notify parent component
      onLoginAttempt(username, password, false);
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
              <Alert variant="destructive" className="animate-pulse-red border-2">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle className="font-bold">SQL Injection Detected!</AlertTitle>
                <AlertDescription>
                  <p>Malicious input pattern detected.</p>
                  <p className="text-xs mt-1 font-mono bg-alert-100 p-1 rounded text-alert-900">
                    Pattern: {attackPattern}
                  </p>
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
