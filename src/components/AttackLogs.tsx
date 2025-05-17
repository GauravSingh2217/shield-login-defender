
import React from 'react';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { FileText, Trash2 } from 'lucide-react';
import { clearSqlInjectionLogs } from '@/utils/sqlInjectionDetector';

interface Log {
  timestamp: string;
  username: string;
  password: string;
  pattern: string;
}

interface AttackLogsProps {
  logs: Log[];
  onClearLogs: () => void;
}

const AttackLogs: React.FC<AttackLogsProps> = ({ logs, onClearLogs }) => {
  const handleClearLogs = () => {
    clearSqlInjectionLogs();
    onClearLogs();
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  return (
    <Card className="w-full shadow-md">
      <CardHeader className="bg-security-700 text-white rounded-t-lg">
        <div className="flex justify-between items-center">
          <div className="flex items-center">
            <FileText className="h-5 w-5 mr-2" />
            <CardTitle>Attack Logs</CardTitle>
          </div>
          <Button 
            variant="outline" 
            size="sm" 
            className="h-8 bg-security-800 text-white hover:bg-security-900 hover:text-white"
            onClick={handleClearLogs}
          >
            <Trash2 className="h-4 w-4 mr-1" /> Clear
          </Button>
        </div>
        <CardDescription className="text-security-200">
          Detected SQL injection attempts are logged here
        </CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        {logs.length > 0 ? (
          <ScrollArea className="h-[300px] p-4">
            {logs.map((log, index) => (
              <div 
                key={index} 
                className="mb-3 p-3 border rounded bg-gray-50 hover:bg-gray-100 transition-colors"
              >
                <div className="flex justify-between mb-1 text-xs text-muted-foreground">
                  <span>#{logs.length - index}</span>
                  <span>{formatTimestamp(log.timestamp)}</span>
                </div>
                <div className="space-y-1 text-sm">
                  <div className="font-semibold">Username:</div>
                  <div className="bg-white p-1 rounded border font-mono text-xs overflow-x-auto">
                    {log.username}
                  </div>
                  <div className="font-semibold">Password:</div>
                  <div className="bg-white p-1 rounded border font-mono text-xs overflow-x-auto">
                    {log.password}
                  </div>
                  <div className="font-semibold">Detected Pattern:</div>
                  <div className="bg-alert-100 text-alert-800 p-1 rounded border font-mono text-xs overflow-x-auto">
                    {log.pattern}
                  </div>
                </div>
              </div>
            ))}
          </ScrollArea>
        ) : (
          <div className="p-8 text-center text-muted-foreground">
            <p>No SQL injection attempts detected yet.</p>
            <p className="text-sm mt-1">Try logging in with a payload like: ' OR 1=1 --</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default AttackLogs;
