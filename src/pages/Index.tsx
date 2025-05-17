
import React, { useState, useEffect } from 'react';
import LoginForm from '@/components/LoginForm';
import AttackLogs from '@/components/AttackLogs';
import SqlInjectionInfo from '@/components/SqlInjectionInfo';
import VulnerableCodeExample from '@/components/VulnerableCodeExample';
import LoginResponse from '@/components/LoginResponse';
import Header from '@/components/Header';
import { getSqlInjectionLogs, countLogsBySeverity, SqlInjectionSeverity } from '@/utils/sqlInjectionDetector';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/components/ui/use-toast';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell } from 'recharts';

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
  
  // Prepare chart data
  const getChartData = () => {
    if (logs.length === 0) return [];
    
    const severityCounts = countLogsBySeverity(logs);
    
    return [
      { name: 'High', value: severityCounts[SqlInjectionSeverity.HIGH] },
      { name: 'Medium', value: severityCounts[SqlInjectionSeverity.MEDIUM] },
      { name: 'Low', value: severityCounts[SqlInjectionSeverity.LOW] }
    ];
  };
  
  // Severity colors
  const severityColors = {
    High: '#e11d48',  // Red
    Medium: '#f97316', // Orange
    Low: '#eab308'    // Yellow
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Header />
      
      <div className="container mx-auto py-8 px-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div className="space-y-8">
            <LoginForm onLoginAttempt={handleLoginAttempt} />
            
            {loginAttempted && (
              <LoginResponse 
                success={loginSuccess} 
                attackDetected={attackDetected}
                username={username}
                severity={attackSeverity}
              />
            )}
            
            <AttackLogs logs={logs} onClearLogs={handleClearLogs} />
          </div>
          
          <div className="space-y-8">
            {logs.length > 0 && (
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-lg">Attack Statistics</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex justify-center">
                    <BarChart
                      width={300}
                      height={200}
                      data={getChartData()}
                      margin={{
                        top: 5,
                        right: 30,
                        left: 20,
                        bottom: 5,
                      }}
                    >
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="name" />
                      <YAxis />
                      <Tooltip />
                      <Bar dataKey="value" fill="#8884d8" name="Count">
                        {getChartData().map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={severityColors[entry.name as keyof typeof severityColors]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </div>
                  <div className="grid grid-cols-3 gap-2 mt-4">
                    {getChartData().map((entry) => (
                      <div key={entry.name} className="text-center">
                        <div className="text-2xl font-bold">{entry.value}</div>
                        <div className="text-sm text-muted-foreground">{entry.name}</div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
            
            <Tabs defaultValue="info" className="w-full">
              <TabsList className="grid grid-cols-2">
                <TabsTrigger value="info">Educational Info</TabsTrigger>
                <TabsTrigger value="code">Code Examples</TabsTrigger>
              </TabsList>
              <TabsContent value="info" className="mt-4">
                <SqlInjectionInfo />
              </TabsContent>
              <TabsContent value="code" className="mt-4">
                <VulnerableCodeExample />
              </TabsContent>
            </Tabs>
            
            <div className="p-4 bg-white rounded-lg shadow">
              <h2 className="text-lg font-medium mb-2">How This Demo Works</h2>
              <Separator className="my-2" />
              <ol className="list-decimal pl-5 space-y-2">
                <li>Enter a username and password in the login form.</li>
                <li>Try using SQL injection patterns like <code className="bg-gray-100 px-1 rounded">&#39; OR 1=1 --</code></li>
                <li>The system scans your input for SQL injection patterns.</li>
                <li>If detected, the attack is logged with severity rating.</li>
                <li>Use the search and filter features to analyze the logs.</li>
                <li>Export logs for further analysis.</li>
                <li>For regular logins, any username &gt;2 chars and password &gt;3 chars will succeed.</li>
              </ol>
              <p className="mt-4 text-sm text-muted-foreground">
                <strong>Note:</strong> This is an educational tool demonstrating detection of SQL 
                injection patterns. In a real application, parameterized queries would be used to prevent 
                such attacks rather than just detecting them.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Index;
