
import React, { useState, useEffect } from 'react';
import InteractiveDashboard from '@/components/InteractiveDashboard';
import { getSqlInjectionLogs, SqlInjectionSeverity } from '@/utils/sqlInjectionDetector';
import { useToast } from '@/components/ui/use-toast';

const Index = () => {
  const [loginAttempted, setLoginAttempted] = useState(false);
  const [loginSuccess, setLoginSuccess] = useState(false);
  const [attackDetected, setAttackDetected] = useState(false);
  const [username, setUsername] = useState('');
  const [logs, setLogs] = useState<any[]>([]);
  const [attackSeverity, setAttackSeverity] = useState<SqlInjectionSeverity | undefined>(undefined);
  const { toast } = useToast();

  // Load logs from localStorage when component mounts
  useEffect(() => {
    updateLogs();
  }, []);

  const updateLogs = () => {
    const attackLogs = getSqlInjectionLogs();
    setLogs(attackLogs.reverse()); // Show newest first
  };

  const handleLoginAttempt = (
    username: string, 
    password: string, 
    isAttack: boolean,
    severity?: SqlInjectionSeverity
  ) => {
    setLoginAttempted(true);
    setUsername(username);
    setAttackDetected(isAttack);
    setAttackSeverity(severity);

    if (isAttack) {
      setLoginSuccess(false);
      
      // Choose toast variant based on severity
      const toastVariant = 
        severity === SqlInjectionSeverity.HIGH ? "destructive" :
        severity === SqlInjectionSeverity.MEDIUM ? "default" : 
        "default";
      
      toast({
        title: "Security Alert",
        description: `SQL injection attempt detected (${severity || 'unknown'} severity) and logged`,
        variant: toastVariant as any,
      });
      updateLogs(); // Update logs after attack detection
    } else {
      // Simulate login logic (in a real app, this would verify credentials)
      const validUsername = username.length > 2 && !username.includes(' ');
      const validPassword = password.length > 3;
      
      setLoginSuccess(validUsername && validPassword);
      
      if (validUsername && validPassword) {
        toast({
          title: "Login Successful",
          description: `Welcome, ${username}!`,
        });
      } else {
        toast({
          title: "Login Failed",
          description: "Invalid username or password",
          variant: "default",
        });
      }
    }
  };

  const handleClearLogs = () => {
    setLogs([]);
    toast({
      title: "Logs Cleared",
      description: "All attack logs have been cleared",
    });
  };

  return (
    <InteractiveDashboard
      loginAttempted={loginAttempted}
      loginSuccess={loginSuccess}
      attackDetected={attackDetected}
      username={username}
      attackSeverity={attackSeverity}
      logs={logs}
      onLoginAttempt={handleLoginAttempt}
      onClearLogs={handleClearLogs}
    />
  );
};

export default Index;
