
import React from 'react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { CheckCircle2, XOctagon } from 'lucide-react';

interface LoginResponseProps {
  success: boolean;
  attackDetected: boolean;
  username: string;
}

const LoginResponse: React.FC<LoginResponseProps> = ({ 
  success, 
  attackDetected, 
  username 
}) => {
  if (attackDetected) {
    return (
      <Alert variant="destructive" className="border-2 animate-pulse">
        <XOctagon className="h-5 w-5" />
        <AlertTitle>Access Denied - Security Alert</AlertTitle>
        <AlertDescription className="mt-2">
          <p>Potential SQL injection attack detected from user input.</p>
          <p className="mt-1">This login attempt has been logged and may be reported.</p>
          <div className="mt-3 bg-white/20 p-2 rounded text-sm">
            <p><strong>Technical details:</strong></p>
            <p>Input flagged for malicious SQL patterns</p>
            <p>IP Address: 192.168.1.xxx (masked for demo)</p>
            <p>Timestamp: {new Date().toLocaleString()}</p>
          </div>
        </AlertDescription>
      </Alert>
    );
  }
  
  if (success) {
    return (
      <Alert className="border-green-500 bg-green-50 text-green-800">
        <CheckCircle2 className="h-5 w-5 text-green-500" />
        <AlertTitle>Login Successful</AlertTitle>
        <AlertDescription>
          Welcome {username}! You have successfully logged in.
        </AlertDescription>
      </Alert>
    );
  }
  
  return (
    <Alert variant="default" className="border-orange-500 bg-orange-50 text-orange-800">
      <XOctagon className="h-5 w-5 text-orange-500" />
      <AlertTitle>Login Failed</AlertTitle>
      <AlertDescription>
        Invalid username or password. Please try again.
      </AlertDescription>
    </Alert>
  );
};

export default LoginResponse;
