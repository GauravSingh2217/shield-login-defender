
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { FileText, Download, Trash2, Search, AlertTriangle, AlertCircle, Info } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { 
  clearSqlInjectionLogs, 
  exportSqlInjectionLogs,
  filterSqlInjectionLogs,
  SqlInjectionLogEntry,
  SqlInjectionSeverity 
} from '@/utils/sqlInjectionDetector';

interface AttackLogsProps {
  logs: SqlInjectionLogEntry[];
  onClearLogs: () => void;
}

const AttackLogs: React.FC<AttackLogsProps> = ({ logs, onClearLogs }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  
  // Apply filters to logs
  const filteredLogs = filterSqlInjectionLogs(logs, {
    severity: selectedSeverity !== 'all' ? selectedSeverity as SqlInjectionSeverity : undefined,
    search: searchTerm || undefined
  });

  const handleClearLogs = () => {
    clearSqlInjectionLogs();
    onClearLogs();
  };

  const handleExportLogs = () => {
    exportSqlInjectionLogs();
  };
  
  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  // Helper functions for severity indicators
  const getSeverityIcon = (severity: SqlInjectionSeverity) => {
    switch (severity) {
      case SqlInjectionSeverity.HIGH:
        return <AlertCircle className="h-4 w-4 text-red-600" />;
      case SqlInjectionSeverity.MEDIUM:
        return <AlertTriangle className="h-4 w-4 text-orange-500" />;
      case SqlInjectionSeverity.LOW:
        return <Info className="h-4 w-4 text-yellow-500" />;
      default:
        return <Info className="h-4 w-4" />;
    }
  };
  
  const getSeverityBadge = (severity: SqlInjectionSeverity) => {
    switch (severity) {
      case SqlInjectionSeverity.HIGH:
        return <Badge variant="destructive">High</Badge>;
      case SqlInjectionSeverity.MEDIUM:
        return <Badge className="bg-orange-500">Medium</Badge>;
      case SqlInjectionSeverity.LOW:
        return <Badge className="bg-yellow-500 text-black">Low</Badge>;
      default:
        return <Badge>Unknown</Badge>;
    }
  };

  const highlightMatchedText = (text: string, matchedText: string) => {
    if (!searchTerm || !text || !matchedText) return text;
    
    try {
      const parts = text.split(new RegExp(`(${matchedText})`, 'gi'));
      return (
        <>
          {parts.map((part, i) => 
            part.toLowerCase() === matchedText.toLowerCase() ? 
              <mark key={i} className="bg-yellow-200 text-black px-1">{part}</mark> : 
              part
          )}
        </>
      );
    } catch (e) {
      return text; // Fallback for any regex issues
    }
  };

  return (
    <Card className="w-full shadow-md">
      <CardHeader className="bg-security-700 text-white rounded-t-lg">
        <div className="flex justify-between items-center">
          <div className="flex items-center">
            <FileText className="h-5 w-5 mr-2" />
            <CardTitle>Attack Logs</CardTitle>
          </div>
          <div className="flex space-x-2">
            <Button 
              variant="outline" 
              size="sm" 
              className="h-8 bg-security-800 text-white hover:bg-security-900 hover:text-white"
              onClick={handleExportLogs}
              disabled={logs.length === 0}
            >
              <Download className="h-4 w-4 mr-1" /> Export
            </Button>
            <Button 
              variant="outline" 
              size="sm" 
              className="h-8 bg-security-800 text-white hover:bg-security-900 hover:text-white"
              onClick={handleClearLogs}
              disabled={logs.length === 0}
            >
              <Trash2 className="h-4 w-4 mr-1" /> Clear
            </Button>
          </div>
        </div>
        <CardDescription className="text-security-200">
          Detected SQL injection attempts are logged here
        </CardDescription>
      </CardHeader>
      
      <div className="px-4 py-2 bg-gray-50 border-b flex flex-col sm:flex-row gap-2">
        <div className="relative flex-grow">
          <Search className="h-4 w-4 absolute left-2 top-2.5 text-gray-400" />
          <Input
            placeholder="Search logs..."
            className="pl-8"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        <div className="w-full sm:w-40">
          <Select value={selectedSeverity} onValueChange={setSelectedSeverity}>
            <SelectTrigger>
              <SelectValue placeholder="Filter by severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severities</SelectItem>
              <SelectItem value={SqlInjectionSeverity.HIGH}>High</SelectItem>
              <SelectItem value={SqlInjectionSeverity.MEDIUM}>Medium</SelectItem>
              <SelectItem value={SqlInjectionSeverity.LOW}>Low</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
      
      <CardContent className="p-0">
        {filteredLogs.length > 0 ? (
          <ScrollArea className="h-[300px]">
            {filteredLogs.map((log, index) => (
              <div 
                key={index} 
                className="p-3 border-b hover:bg-gray-50 transition-colors"
              >
                <div className="flex justify-between mb-1 text-xs text-muted-foreground">
                  <span>#{logs.length - index}</span>
                  <span>{formatTimestamp(log.timestamp)}</span>
                </div>
                <div className="space-y-1 text-sm">
                  <div className="flex justify-between items-center">
                    <span className="font-semibold">{log.description}</span>
                    <div className="flex items-center">
                      {getSeverityIcon(log.severity)}
                      <span className="ml-1">{getSeverityBadge(log.severity)}</span>
                    </div>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2">
                    <div>
                      <div className="font-semibold text-xs text-muted-foreground">Username:</div>
                      <div className="bg-white p-1 rounded border font-mono text-xs overflow-x-auto">
                        {highlightMatchedText(log.username, log.matchedText)}
                      </div>
                    </div>
                    <div>
                      <div className="font-semibold text-xs text-muted-foreground">Password:</div>
                      <div className="bg-white p-1 rounded border font-mono text-xs overflow-x-auto">
                        {highlightMatchedText(log.password, log.matchedText)}
                      </div>
                    </div>
                  </div>
                  <div>
                    <div className="font-semibold text-xs text-muted-foreground">Matched Text:</div>
                    <div className="bg-alert-100 text-alert-800 p-1 rounded border font-mono text-xs overflow-x-auto">
                      <mark className="bg-yellow-300 text-black px-1">{log.matchedText}</mark>
                    </div>
                  </div>
                  <div>
                    <div className="font-semibold text-xs text-muted-foreground">Pattern:</div>
                    <div className="bg-white p-1 rounded border font-mono text-xs overflow-x-auto">
                      {log.pattern}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </ScrollArea>
        ) : (
          <div className="p-8 text-center text-muted-foreground">
            {logs.length > 0 ? (
              <p>No logs match your search criteria.</p>
            ) : (
              <>
                <p>No SQL injection attempts detected yet.</p>
                <p className="text-sm mt-1">Try logging in with a payload like: ' OR 1=1 --</p>
              </>
            )}
          </div>
        )}
      </CardContent>
      
      <CardFooter className="bg-gray-50 border-t py-2 text-xs text-muted-foreground">
        <div className="w-full flex justify-between items-center">
          <span>Total logs: {logs.length}</span>
          <span>Showing: {filteredLogs.length} of {logs.length}</span>
        </div>
      </CardFooter>
    </Card>
  );
};

export default AttackLogs;
