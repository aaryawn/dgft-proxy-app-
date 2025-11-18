import axios from 'axios';

// Types - shared between frontend and backend
export interface DGFTCredentials {
  clientId: string;
  clientSecret: string;
  xApiKey: string;
  dgftPublicKey: string;
  userPrivateKey: string;
  userPublicKey: string;
  iecCode: string;
}

export interface AccessTokenResponse {
  accessToken: string;
  expiresIn: number;
  client_id: string;
}

export interface EncryptedPayload {
  data: string;
  sign: string;
}

/**
 * Generate unique messageID per DGFT API requirement (Section 3, Step 6)
 */
function generateMessageID(): string {
  return `MSG-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

export interface DGFTError {
  code: string;
  message: string;
  description?: string;
}

export interface PushIRMToGenEBRCRequest {
  iecNumber: string;
  requestId: string;
  recordResCount: number;
  uploadType: 101 | 102 | 103 | 104;
  decalarationFlag: 'Y';
  ebrcBulkGenDtos: any[];
}

export interface PushIRMToGenEBRCResponse {
  dgftAckId: string;
  requestId: string;
  ackStatus: 'Validated' | 'Failed';
  recordResCount: number;
  errorDetails: any[];
}

export interface GetRequestStatusRequest {
  requestId: string;
}

export interface GetRequestStatusResponse {
  dgftAckId: string;
  requestId: string;
  recordResCount: number;
  recordProCount: number;
  recordFailCount: number;
  processingStatus: 'Processed' | 'Errored';
  ebrcBulkGenStatusLst: any[];
}

export interface IRMRequest {
  irmFromDate?: string;
  irmToDate?: string;
  irmNumber?: string;
  iecCode: string;
}

export interface IRMResponse {
  irmIssueDate: string;
  irmNumber: string;
  irmStatus: 'F' | 'A' | 'C';
  ifscCode: string;
  remittanceAdCode: string;
  remittanceDate: string;
  remittanceFCC: string;
  remittanceFCCAmount: number;
  ormAmountFCC: number | null;
  irmAvailableAmt: number;
  irmUtilizedAmt: number;
  iecCode?: string;
  panNumber: string;
  remitterName: string;
  remitterCountry: string;
  purposeOfRemittance: string;
}

export interface IRMDetailsResponse {
  irmResplst: IRMResponse[];
}

export interface ORMRequest {
  ormFromDate?: string;
  ormToDate?: string;
  ormNumber?: string;
  IecCode: string;
}

export interface ORMResponse {
  ormIssueDate: string;
  ormNumber: string;
  ormStatus: 'F' | 'A' | 'C';
  ifscCode: string;
  ornAdCode: string;
  paymentDate: string;
  ornFCC: string;
  ornFCAmount: number;
  iecCode?: string;
  panNumber: string;
  beneficiaryName: string;
  beneficiaryCountry: string;
  purposeOfOutward: string;
  referenceIRM: string;
}

export interface ORMDetailsResponse {
  ormResplst: ORMResponse[];
}

// Crypto functions are lazy-loaded to prevent FUNCTION_INVOCATION_FAILED
// import { encryptClientSecret, prepareEncryptedPayload, decryptResponse } from '../lib/dgftCrypto';
import {
  logApiRequest,
  logApiResponse,
  logApiError,
  logInfo,
  logWarn
} from '../utils/logger';

// Use proxy if DGFT_PROXY_URL is set, otherwise direct connection
const DGFT_PROXY_URL = process.env.DGFT_PROXY_URL || '';
const API_BASE_URL = DGFT_PROXY_URL 
  ? `${DGFT_PROXY_URL}/genebrc`
  : 'https://apiservices.dgft.gov.in/genebrc';

/**
 * Parse DGFT error response
 */
function parseError(error: any): DGFTError {
  if (error.response?.data) {
    const data = error.response.data;
    if (data.errorCode || data.error) {
      return {
        code: data.errorCode || data.error || 'UNKNOWN',
        message: data.errorDescription || data.message || 'An error occurred',
        description: data.errorDetails || data.description
      };
    }
  }
  if (error.message) {
    return {
      code: 'NETWORK_ERROR',
      message: error.message
    };
  }
  return {
    code: 'UNKNOWN_ERROR',
    message: 'An unknown error occurred'
  };
}

/**
 * Get credentials from environment variables
 */
export function getCredentials(): DGFTCredentials {
  return {
    clientId: process.env.DGFT_CLIENT_ID || '',
    clientSecret: process.env.DGFT_CLIENT_SECRET || '',
    xApiKey: process.env.DGFT_X_API_KEY || '',
    dgftPublicKey: process.env.DGFT_DGFT_PUBLIC_KEY || '',
    userPrivateKey: process.env.DGFT_USER_PRIVATE_KEY || '',
    userPublicKey: process.env.DGFT_USER_PUBLIC_KEY || '',
    iecCode: process.env.DGFT_IEC_CODE || ''
  };
}

/**
 * Get access token from DGFT API
 */
export async function getAccessToken(credentials: DGFTCredentials): Promise<AccessTokenResponse> {
  const startTime = Date.now();
  const requestId = `TOKEN-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  
  if (!credentials.clientId || !credentials.clientSecret || !credentials.xApiKey) {
    logApiError('getAccessToken', new Error('DGFT credentials not provided'), requestId);
    throw new Error('DGFT credentials not provided');
  }
  
  const url = `${API_BASE_URL}/getAccessToken`;
  logApiRequest('getAccessToken', url, 'POST', {
    'Content-Type': 'application/json',
    'x-api-key': '[REDACTED]'
  }, {
    client_id: credentials.clientId,
    client_secret: '[ENCRYPTED]'
  }, requestId);
  
  // Validate client secret before encryption
  if (!credentials.clientSecret || credentials.clientSecret.trim().length === 0) {
    const error = new Error('Client secret is empty or invalid');
    logApiError('getAccessToken', error, requestId, url, 500);
    (error as any).statusCode = 500;
    throw error;
  }
  
  // Lazy-load crypto function to prevent FUNCTION_INVOCATION_FAILED
  const { encryptClientSecret } = await import('../lib/dgftCrypto');
  
  // Encrypt client secret with error handling
  let encryptedClientSecret: string;
  try {
    encryptedClientSecret = await encryptClientSecret(credentials.clientSecret);
    logInfo('✅ Client secret encrypted successfully', {
      requestId,
      encryptedLength: encryptedClientSecret.length
    });
  } catch (encryptError: any) {
    logApiError('getAccessToken', encryptError, requestId, url, 500);
    logInfo('❌ Encryption failed', {
      requestId,
      errorType: encryptError?.constructor?.name || 'Unknown',
      errorMessage: encryptError?.message || 'Unknown error',
      errorStack: encryptError?.stack || 'No stack trace'
    });
    const error = new Error(`Encryption failed: ${encryptError?.message || 'Unknown error'}`);
    (error as any).statusCode = 500;
    (error as any).originalError = encryptError;
    throw error;
  }
  
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': credentials.xApiKey
      },
      body: JSON.stringify({
        client_id: credentials.clientId,
        client_secret: encryptedClientSecret
      })
    });
    
    const duration = Date.now() - startTime;
    const responseSize = response.headers.get('content-length') || 'unknown';
    
    logInfo('📡 DGFT API Response received', {
      operation: 'getAccessToken',
      requestId,
      statusCode: Number(response.status),
      statusText: response.statusText,
      durationMs: `${duration}ms`,
      responseSize,
      ok: response.ok
    });
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      
      // Log full error data for debugging
      logInfo('🚨 DGFT API Error Response', {
        requestId,
        statusCode: response.status,
        statusText: response.statusText,
        errorData: JSON.stringify(errorData)
      });
      
      // Extract error details from DGFT response
      const errorCode = errorData.errorCode || errorData.error || String(response.status);
      const errorDescription = errorData.errorDescription || errorData.message || response.statusText;
      
      // For 403 errors, provide specific IP whitelisting message
      if (response.status === 403) {
        const ipWhitelistMessage = `IP Whitelisting Required: ${errorDescription}. Your server IP address needs to be whitelisted in the DGFT portal. Please contact your DGFT administrator to add your server IP address.`;
        logApiError('getAccessToken', {
          response: { data: errorData },
          message: ipWhitelistMessage,
          statusCode: response.status
        }, requestId, url, Number(response.status));
        const error = new Error(ipWhitelistMessage);
        (error as any).statusCode = 403;
        (error as any).isIPWhitelistError = true;
        throw error;
      }
      
      // For 401 errors, provide specific auth message
      if (response.status === 401) {
        const authMessage = `Authentication Failed: ${errorDescription}. Please verify your client_id, client_secret, and x-api-key credentials.`;
        logApiError('getAccessToken', {
          response: { data: errorData },
          message: authMessage,
          statusCode: response.status
        }, requestId, url, Number(response.status));
        const error = new Error(authMessage);
        (error as any).statusCode = 401;
        (error as any).isAuthError = true;
        throw error;
      }
      
      // For other errors, show the actual DGFT error
      const errorMessage = `DGFT API Error (${errorCode}): ${errorDescription}`;
      logApiError('getAccessToken', {
        response: { data: errorData },
        message: errorMessage,
        statusCode: response.status
      }, requestId, url, Number(response.status));
      const error = new Error(errorMessage);
      (error as any).statusCode = response.status;
      throw error;
    }
    
    const data: AccessTokenResponse = await response.json();
    
    logApiResponse('getAccessToken', response.status, duration, {
      hasAccessToken: !!data.accessToken,
      expiresIn: data.expiresIn,
      client_id: data.client_id
    }, requestId);
    
    return data;
  } catch (error: any) {
    const duration = Date.now() - startTime;
    
    // If error already has statusCode and metadata (from our specific error handling above), preserve it
    if (error?.statusCode && (error?.isIPWhitelistError || error?.isAuthError)) {
      logApiError('getAccessToken', error, requestId, url, Number(error.statusCode));
      throw error; // Re-throw the error with metadata intact
    }
    
    // Enhanced error logging for 500 errors
    const statusCode = error?.response?.status || error?.statusCode || 500;
    logApiError('getAccessToken', error, requestId, url, Number(statusCode));
    
    // Log detailed error information for debugging
    logInfo('🔍 Detailed Error Information', {
      requestId,
      errorType: error?.constructor?.name || typeof error,
      errorName: error?.name || 'Unknown',
      errorMessage: error?.message || 'No message',
      errorStack: error?.stack || 'No stack trace',
      statusCode: Number(statusCode),
      hasOriginalError: !!error?.originalError,
      originalErrorMessage: error?.originalError?.message,
      credentialsPresent: {
        hasClientId: !!credentials.clientId,
        hasClientSecret: !!credentials.clientSecret,
        hasXApiKey: !!credentials.xApiKey,
        clientSecretLength: credentials.clientSecret?.length || 0
      }
    });
    
    // For network errors or other unexpected errors, parse and log
    const dgftError = parseError(error);
    const errorMessage = `Failed to get access token: ${dgftError.message} (${dgftError.code})`;
    const apiError = new Error(errorMessage);
    (apiError as any).statusCode = statusCode;
    (apiError as any).originalError = error;
    throw apiError;
  }
}

/**
 * Fetch IRM Details
 */
export async function fetchIRMDetails(
  accessToken: string,
  credentials: DGFTCredentials,
  request: IRMRequest
): Promise<IRMDetailsResponse> {
  const startTime = Date.now();
  const requestId = `IRM-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const url = `${API_BASE_URL}/fetchIRMDetails`;
  
  // Lazy-load crypto function to prevent FUNCTION_INVOCATION_FAILED
  const { prepareEncryptedPayload } = await import('../lib/dgftCrypto');
  
  const { payload, secretVal, secretKey } = await prepareEncryptedPayload(
    request,
    credentials.userPrivateKey,
    credentials.dgftPublicKey
  );
  
  logInfo('🔐 Encryption Details for IRM Fetch', {
    requestId,
    secretKeyLength: secretKey.length,
    secretValLength: secretVal.length,
    payloadDataLength: payload.data.length,
    signatureLength: payload.sign.length,
    hasSecretKey: !!secretKey,
    hasSecretVal: !!secretVal
  });
  
  // Generate messageID per DGFT API requirement (Section 3, Step 6)
  const messageID = generateMessageID();
  
  // Validate messageID was generated correctly
  if (!messageID || messageID.trim().length === 0) {
    const error = new Error('messageID generation failed');
    logApiError('fetchIRMDetails', error, requestId, url, 500);
    throw error;
  }
  
  logInfo('🔍 messageID Generated', {
    requestId,
    messageID,
    hasMessageID: !!messageID,
    messageIDLength: messageID.length
  });
  
  logApiRequest('fetchIRMDetails', url, 'POST', {
    'Content-Type': 'application/json',
    'accessToken': '[REDACTED]',
    'client_id': credentials.clientId,
    'secretVal': '[REDACTED]',
    'messageID': messageID
  }, {
    data: '[ENCRYPTED]',
    sign: '[ENCRYPTED]'
  }, requestId);
  
  logInfo('📋 IRM Request Details', {
    requestId,
    iecCode: request.iecCode,
    irmNumber: request.irmNumber,
    irmFromDate: request.irmFromDate,
    irmToDate: request.irmToDate
  });
  
  // Validate encryption outputs before sending
  if (!payload.data || payload.data.trim().length === 0) {
    const error = new Error('Encrypted payload data is empty');
    logApiError('fetchIRMDetails', error, requestId, url, 500);
    throw error;
  }
  
  if (!payload.sign || payload.sign.trim().length === 0) {
    const error = new Error('Digital signature is empty');
    logApiError('fetchIRMDetails', error, requestId, url, 500);
    throw error;
  }
  
  if (!secretVal || secretVal.trim().length === 0) {
    const error = new Error('Encrypted secret key (secretVal) is empty');
    logApiError('fetchIRMDetails', error, requestId, url, 500);
    throw error;
  }
  
  // Validate access token before sending
  if (!accessToken || accessToken.trim().length === 0) {
    const error = new Error('Access token is empty or invalid');
    logApiError('fetchIRMDetails', error, requestId, url, 400);
    throw error;
  }
  
  // Per DGFT API Documentation Section 5.2 and Section 3 Step 6 - Exact header format required
  // Headers: Content-Type, accessToken, client_id, secretVal, x-api-key, messageID
  
  // Explicitly verify messageID exists before creating headers
  if (!messageID || typeof messageID !== 'string' || messageID.trim().length === 0) {
    const error = new Error(`messageID is invalid: ${messageID}`);
    logApiError('fetchIRMDetails', error, requestId, url, 500);
    throw error;
  }
  
  // Create headers object with explicit messageID inclusion
  const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'accessToken': accessToken,
        'client_id': credentials.clientId,
    'secretVal': secretVal,
    'x-api-key': credentials.xApiKey,
    'messageID': messageID
  };
  
  // Explicitly ensure messageID is in headers (fallback)
  if (!('messageID' in headers) || !headers['messageID']) {
    headers['messageID'] = messageID;
    logInfo('⚠️ messageID was missing, added as fallback', { requestId, messageID });
  }
  
  // Validate all required headers are present
  const requiredHeaders = ['Content-Type', 'accessToken', 'client_id', 'secretVal', 'x-api-key', 'messageID'];
  const missingHeaders = requiredHeaders.filter(h => !(h in headers) || !headers[h] || headers[h].trim().length === 0);
  if (missingHeaders.length > 0) {
    const error = new Error(`Missing required headers: ${missingHeaders.join(', ')}`);
    logApiError('fetchIRMDetails', error, requestId, url, 500);
    throw error;
  }
  
  // Log headers with messageID visible for debugging
  logInfo('✅ Headers Created with messageID', {
    requestId,
    headerKeys: Object.keys(headers),
    headerCount: Object.keys(headers).length,
    messageID: headers['messageID'],
    hasMessageID: 'messageID' in headers && !!headers['messageID']
  });
  
  // Log exact headers being sent (per DGFT API Documentation Section 5.2)
  logInfo('📤 Sending DGFT API Request', {
    requestId,
    url,
    method: 'POST',
    headers: {
      'Content-Type': headers['Content-Type'],
      'accessToken': '[REDACTED]',
      'client_id': headers['client_id'],
      'secretVal': '[REDACTED]',
      'x-api-key': '[REDACTED]',
      'messageID': headers['messageID']
    },
    bodyStructure: {
      hasData: !!payload.data,
      dataLength: payload.data.length,
      hasSign: !!payload.sign,
      signLength: payload.sign.length,
      dataPreview: payload.data.substring(0, 50) + '...',
      signPreview: payload.sign.substring(0, 50) + '...'
    },
    encryptionValidation: {
      secretValLength: secretVal.length,
      secretValPreview: secretVal.substring(0, 50) + '...',
      payloadDataIsBase64: /^[A-Za-z0-9+/=]+$/.test(payload.data),
      payloadSignIsBase64: /^[A-Za-z0-9+/=]+$/.test(payload.sign),
      secretValIsBase64: /^[A-Za-z0-9+/=]+$/.test(secretVal)
    },
    requestPayload: {
      iecCode: request.iecCode,
      irmNumber: request.irmNumber,
      irmFromDate: request.irmFromDate,
      irmToDate: request.irmToDate
    }
    });
    
    try {
      // Log the exact request structure before sending
      const requestBody = JSON.stringify(payload);
      
      // Final verification: Ensure messageID is still in headers before fetch
      if (!('messageID' in headers) || !headers['messageID']) {
        headers['messageID'] = messageID;
        logInfo('⚠️ messageID missing before fetch, re-added', { requestId, messageID });
      }
      
      // Log headers validation right before fetch with messageID visible
      logInfo('🔍 Headers Before Fetch', {
        requestId,
        headerKeys: Object.keys(headers),
        headerCount: Object.keys(headers).length,
        hasMessageID: 'messageID' in headers,
        messageIDValue: headers['messageID'],
        messageIDLength: headers['messageID']?.length || 0,
        allHeaders: {
          'Content-Type': headers['Content-Type'],
          'accessToken': '[REDACTED]',
          'client_id': headers['client_id'],
          'secretVal': '[REDACTED]',
          'x-api-key': '[REDACTED]',
          'messageID': headers['messageID'] // Show actual value
        },
        requiredHeaders: ['Content-Type', 'accessToken', 'client_id', 'secretVal', 'x-api-key', 'messageID'],
        allRequiredPresent: requiredHeaders.every(h => h in headers && headers[h] && headers[h].trim().length > 0)
      });
      
      logInfo('🔍 Exact Request Structure', {
      requestId,
      url,
      method: 'POST',
      headersObject: headers,
      headerCount: Object.keys(headers).length,
      bodyLength: requestBody.length,
      bodyIsValidJSON: (() => {
        try {
          JSON.parse(requestBody);
          return true;
        } catch {
          return false;
        }
      })(),
      bodyStructure: {
        hasData: !!payload.data,
        hasSign: !!payload.sign,
        dataType: typeof payload.data,
        signType: typeof payload.sign
      }
    });
    
    // Per DGFT API Documentation Section 5.2 - exact header format
    // Use axios to preserve exact header case (accessToken, secretVal, messageID)
    // Node.js fetch lowercases headers, but DGFT gateway requires exact camelCase
    const axiosHeaders = {
      'Content-Type': 'application/json',
      'accessToken': accessToken,  // Exact case - must match DGFT requirement
      'client_id': credentials.clientId,
      'secretVal': secretVal,      // Exact case - must match DGFT requirement
      'x-api-key': credentials.xApiKey, // Added per DGFT gateway requirement
      'messageID': messageID      // Exact case - must match DGFT requirement
    };
    
    // Log final headers being sent
    logInfo('🚀 Final Headers Being Sent (Axios - Preserves Case)', {
      requestId,
      headerCount: Object.keys(axiosHeaders).length,
      headerKeys: Object.keys(axiosHeaders),
      hasMessageID: 'messageID' in axiosHeaders,
      messageIDValue: axiosHeaders['messageID'],
      headerCase: 'Axios preserves exact case: accessToken, secretVal, messageID'
    });
    
    let response: any;
    let duration: number;
    let responseSize: string;
    let responseHeaders: Record<string, string>;
    
    try {
      const startFetch = Date.now();
      const axiosResponse = await axios.post(url, JSON.parse(requestBody), {
        headers: axiosHeaders,
        timeout: 30000,
        validateStatus: () => true // Don't throw on any status code
      });
      
      duration = Date.now() - startFetch;
      responseSize = axiosResponse.headers['content-length'] || 'unknown';
      responseHeaders = axiosResponse.headers as Record<string, string>;
      
      // Convert axios response to fetch-like format for compatibility
      response = {
        status: axiosResponse.status,
        statusText: axiosResponse.statusText,
        ok: axiosResponse.status >= 200 && axiosResponse.status < 300,
        headers: {
          get: (key: string) => axiosResponse.headers[key.toLowerCase()] || null,
          forEach: (callback: (value: string, key: string) => void) => {
            Object.entries(axiosResponse.headers).forEach(([k, v]) => callback(String(v), k));
          },
          entries: () => Object.entries(axiosResponse.headers).map(([k, v]) => [k, String(v)] as [string, string])
        },
        json: async () => axiosResponse.data,
        text: async () => typeof axiosResponse.data === 'string' ? axiosResponse.data : JSON.stringify(axiosResponse.data)
      };
      
      logInfo('📡 DGFT API Response received', {
        operation: 'fetchIRMDetails',
        requestId,
        statusCode: Number(response.status),
        statusText: response.statusText,
        durationMs: `${duration}ms`,
        responseSize,
        ok: response.ok,
        isIPWhitelistError: response.status === 403,
        isAuthError: response.status === 401,
        responseHeaders: responseHeaders
      });
    } catch (axiosError: any) {
      duration = Date.now() - startTime;
      responseSize = 'unknown';
      responseHeaders = {};
      
      // Handle axios errors
      if (axiosError.response) {
        // Server responded with error status
        response = {
          status: axiosError.response.status,
          statusText: axiosError.response.statusText || 'Error',
          ok: false,
          headers: {
            get: (key: string) => axiosError.response?.headers[key.toLowerCase()] || null,
            forEach: (callback: (value: string, key: string) => void) => {
              if (axiosError.response?.headers) {
                Object.entries(axiosError.response.headers).forEach(([k, v]) => callback(String(v), k));
              }
            },
            entries: () => axiosError.response?.headers 
              ? Object.entries(axiosError.response.headers).map(([k, v]) => [k, String(v)] as [string, string])
              : []
          },
          json: async () => axiosError.response?.data || {},
          text: async () => typeof axiosError.response?.data === 'string' 
            ? axiosError.response.data 
            : JSON.stringify(axiosError.response?.data || {})
        };
        
        responseHeaders = axiosError.response.headers as Record<string, string>;
        
        logInfo('📡 DGFT API Response received (from axios error)', {
          operation: 'fetchIRMDetails',
          requestId,
          statusCode: Number(response.status),
          statusText: response.statusText,
          durationMs: `${duration}ms`,
          responseSize,
          ok: false,
          isIPWhitelistError: response.status === 403,
          isAuthError: response.status === 401
        });
      } else {
        // Network or other error
        throw new Error(`Network error: ${axiosError.message || 'Unknown error'}`);
      }
    }
    
    if (!response.ok) {
      // Try to get response as text first to see what we actually received
      const responseText = await response.text().catch(() => '');
      let errorData: any = {};
      
      // Try to parse as JSON if there's content
      if (responseText && responseText.trim().length > 0) {
        try {
          errorData = JSON.parse(responseText);
        } catch {
          // Not JSON, use text as error message
          errorData = { message: responseText, rawResponse: responseText };
        }
      }
      
      // Log full error data for debugging including headers
      logInfo('🚨 DGFT API Error Response', {
        requestId,
        statusCode: response.status,
        statusText: response.statusText,
        responseHeaders: responseHeaders,
        responseBody: responseText,
        errorData: JSON.stringify(errorData),
        hasResponseBody: responseText.length > 0
      });
      
      // Extract error details from DGFT response
      const errorCode = errorData.errorCode || errorData.error || String(response.status);
      const errorDescription = errorData.errorDescription || errorData.message || errorData.errorMessage || errorData.rawResponse || response.statusText;
      
      // Check if error message actually mentions IP whitelisting (not just "forbidden" which is generic)
      const errorText = JSON.stringify(errorData).toLowerCase();
      const isActuallyIPError = (errorText.includes('ip') && errorText.includes('whitelist')) || 
                                errorText.includes('ip address') || 
                                errorText.includes('whitelisted');
      
      // For 403 errors, check if it's actually IP whitelisting or something else
      if (response.status === 403) {
        // Log detailed request information for debugging
        logInfo('🔍 403 Error - Complete Request Analysis', {
          requestId,
          requestHeaders: {
            exactHeaders: Object.keys(headers).map(k => ({ key: k, hasValue: !!headers[k], valueLength: headers[k]?.length || 0 })),
            allHeaderKeys: Object.keys(headers),
            headerCount: Object.keys(headers).length,
            'Content-Type': headers['Content-Type'],
            'accessToken': '[REDACTED]',
            'client_id': headers['client_id'],
            'secretVal': '[REDACTED]',
            'messageID': headers['messageID']
          },
          headerComparison: {
            workingGetAccessToken: {
              headers: ['Content-Type', 'x-api-key'],
              count: 2,
              note: 'getAccessToken uses x-api-key (section 5.1)'
            },
            fetchIRMDetails: {
              headers: Object.keys(headers),
              count: Object.keys(headers).length,
              note: 'fetchIRMDetails per section 5.2 & 3.6: Content-Type, accessToken, client_id, secretVal, messageID (NO x-api-key)'
            }
          },
          requestBody: {
            hasData: !!payload.data,
            dataLength: payload.data.length,
            hasSign: !!payload.sign,
            signLength: payload.sign.length,
            dataIsBase64: /^[A-Za-z0-9+/=]+$/.test(payload.data),
            signIsBase64: /^[A-Za-z0-9+/=]+$/.test(payload.sign)
          },
          responseDetails: {
            statusCode: response.status,
            statusText: response.statusText,
            responseBodyLength: responseText.length,
            responseBodyEmpty: responseText.length === 0,
            responseBodyContent: responseText.substring(0, 500),
            responseHeaders: Object.fromEntries(response.headers.entries())
          },
          errorData: errorData,
          possibleCauses: [
            'Header format mismatch (case sensitivity)',
            'Missing required headers',
            'Encryption format incorrect',
            'Signature format incorrect',
            'Request body structure incorrect',
            'Access token invalid or expired',
            'Client ID mismatch'
          ]
        });
        
        if (isActuallyIPError) {
        const ipWhitelistMessage = `IP Whitelisting Required: ${errorDescription}. Your server IP address needs to be whitelisted in the DGFT portal. Please contact your DGFT administrator to add your server IP address.`;
        const error = new Error(ipWhitelistMessage);
        (error as any).statusCode = 403;
        (error as any).isIPWhitelistError = true;
          (error as any).response = { data: errorData };
          logApiError('fetchIRMDetails', error, requestId, url, Number(response.status));
        throw error;
        } else {
          // 403 but not IP whitelisting - likely encryption/signature/format issue
          // Show the actual error from DGFT
          const actualError = typeof errorData === 'object' && errorData !== null && Object.keys(errorData).length > 0
            ? JSON.stringify(errorData, null, 2)
            : (responseText.length > 0 ? responseText : 'Empty response body - DGFT rejected request before processing');
          
          const errorMessage = `DGFT API Error (403): ${errorDescription || actualError || 'Forbidden'}. This may be due to encryption, signature, or request format issues. Full error: ${actualError}. Check logs for detailed request/response information.`;
          const apiError = new Error(errorMessage);
          (apiError as any).statusCode = 403;
          (apiError as any).isIPWhitelistError = false;
          (apiError as any).response = { data: errorData };
          (apiError as any).requestDetails = {
            headers: Object.keys(headers),
            bodyStructure: {
              hasData: !!payload.data,
              dataLength: payload.data.length,
              hasSign: !!payload.sign,
              signLength: payload.sign.length
            }
          };
          logApiError('fetchIRMDetails', apiError, requestId, url, Number(response.status));
          throw apiError;
        }
      }
      
      // For 401 errors, provide specific auth message
      if (response.status === 401) {
        const authMessage = `Authentication Failed: ${errorDescription}. Please verify your client_id, client_secret, and x-api-key credentials.`;
        const error = new Error(authMessage);
        (error as any).statusCode = 401;
        (error as any).isAuthError = true;
        (error as any).response = { data: errorData };
        logApiError('fetchIRMDetails', error, requestId, url, Number(response.status));
        throw error;
      }
      
      // For other errors, show the actual DGFT error
      const actualError = typeof errorData === 'object' && errorData !== null ? JSON.stringify(errorData, null, 2) : String(errorData);
      const errorMessage = `DGFT API Error (${errorCode}): ${errorDescription || actualError}`;
      const error = new Error(errorMessage);
      (error as any).statusCode = response.status;
      (error as any).response = { data: errorData };
      logApiError('fetchIRMDetails', error, requestId, url, Number(response.status));
      throw error;
    }
    
    const encryptedResponse: EncryptedPayload = await response.json();
    
    logInfo('🔓 Decrypting IRM response', { requestId });
    
    // Lazy-load crypto function to prevent FUNCTION_INVOCATION_FAILED
    const { decryptResponse } = await import('../lib/dgftCrypto');
    
    const decryptedData = await decryptResponse(
      encryptedResponse.data,
      encryptedResponse.sign,
      secretKey,
      credentials.dgftPublicKey,
      credentials.userPrivateKey
    ) as IRMDetailsResponse;
    
    logApiResponse('fetchIRMDetails', Number(response.status), duration, {
      recordCount: decryptedData.irmResplst?.length || 0,
      hasRecords: (decryptedData.irmResplst?.length || 0) > 0
    }, requestId);
    
    return decryptedData;
  } catch (error: any) {
    const duration = Date.now() - startTime;
    const dgftError = parseError(error);
    logApiError('fetchIRMDetails', error, requestId, url, Number(error?.response?.status || error?.statusCode || 0));
    throw new Error(`Failed to fetch IRM details: ${dgftError.message} (${dgftError.code})`);
  }
}

/**
 * Fetch ORM Details
 */
export async function fetchORMDetails(
  accessToken: string,
  credentials: DGFTCredentials,
  request: ORMRequest
): Promise<ORMDetailsResponse> {
  const startTime = Date.now();
  const requestId = `ORM-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const url = `${API_BASE_URL}/fetchORMDetails`;
  
  // Lazy-load crypto function to prevent FUNCTION_INVOCATION_FAILED
  const { prepareEncryptedPayload } = await import('../lib/dgftCrypto');
  
  const { payload, secretVal, secretKey } = await prepareEncryptedPayload(
    request,
    credentials.userPrivateKey,
    credentials.dgftPublicKey
  );
  
  // Generate messageID for this request
  const messageID = generateMessageID();
  
  // Validate messageID was generated correctly
  if (!messageID || messageID.trim().length === 0) {
    const error = new Error('messageID generation failed');
    logApiError('fetchORMDetails', error, requestId, url, 500);
    throw error;
  }
  
  logInfo('🔍 messageID Generated', {
    requestId,
    messageID,
    hasMessageID: !!messageID,
    messageIDLength: messageID.length
  });
  
  logApiRequest('fetchORMDetails', url, 'POST', {
    'Content-Type': 'application/json',
    'accessToken': '[REDACTED]',
    'client_id': credentials.clientId,
    'secretVal': '[REDACTED]',
    'messageID': messageID
  }, {
    data: '[ENCRYPTED]',
    sign: '[ENCRYPTED]'
  }, requestId);
  
  logInfo('📋 ORM Request Details', {
    requestId,
    IecCode: request.IecCode,
    ormNumber: request.ormNumber,
    ormFromDate: request.ormFromDate,
    ormToDate: request.ormToDate
  });
  
  try {
    // Per DGFT API Documentation Section 5.3 & Section 3 Step 6 - same header format as fetchIRMDetails
    // Headers: Content-Type, accessToken, client_id, secretVal, messageID (NO x-api-key)
    
    // Explicitly verify messageID exists
    if (!messageID || typeof messageID !== 'string' || messageID.trim().length === 0) {
      const error = new Error(`messageID is invalid: ${messageID}`);
      logApiError('fetchORMDetails', error, requestId, url, 500);
      throw error;
    }
    
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'accessToken': accessToken,
        'client_id': credentials.clientId,
      'secretVal': secretVal,
      'x-api-key': credentials.xApiKey,
      'messageID': messageID
    };
    
    // Explicitly ensure messageID is in headers (fallback)
    if (!('messageID' in headers) || !headers['messageID']) {
      headers['messageID'] = messageID;
      logInfo('⚠️ messageID was missing, added as fallback', { requestId, messageID });
    }
    
    // Validate all required headers are present
    const requiredHeaders = ['Content-Type', 'accessToken', 'client_id', 'secretVal', 'x-api-key', 'messageID'];
    const missingHeaders = requiredHeaders.filter(h => !(h in headers) || !headers[h] || headers[h].trim().length === 0);
    if (missingHeaders.length > 0) {
      const error = new Error(`Missing required headers: ${missingHeaders.join(', ')}`);
      logApiError('fetchORMDetails', error, requestId, url, 500);
      throw error;
    }
    
    // Final verification before fetch
    if (!('messageID' in headers) || !headers['messageID']) {
      headers['messageID'] = messageID;
      logInfo('⚠️ messageID missing before fetch, re-added', { requestId, messageID });
    }
    
    // Log headers validation right before fetch
    logInfo('🔍 Headers Before Fetch', {
      requestId,
      headerKeys: Object.keys(headers),
      headerCount: Object.keys(headers).length,
      hasMessageID: 'messageID' in headers,
      messageIDValue: headers['messageID'],
      messageIDLength: headers['messageID']?.length || 0,
      allRequiredPresent: requiredHeaders.every(h => h in headers && headers[h] && headers[h].trim().length > 0)
    });
    
    // Use axios to preserve exact header case
    const axiosHeaders = {
      'Content-Type': 'application/json',
      'accessToken': accessToken,
      'client_id': credentials.clientId,
      'secretVal': secretVal,
      'x-api-key': credentials.xApiKey,
      'messageID': messageID
    };
    
    let response: any;
    let duration: number;
    let responseSize: string;
    
    try {
      const startFetch = Date.now();
      const axiosResponse = await axios.post(url, payload, {
        headers: axiosHeaders,
        timeout: 30000,
        validateStatus: () => true
      });
      
      duration = Date.now() - startFetch;
      responseSize = axiosResponse.headers['content-length'] || 'unknown';
      
      response = {
        status: axiosResponse.status,
        statusText: axiosResponse.statusText,
        ok: axiosResponse.status >= 200 && axiosResponse.status < 300,
        headers: {
          get: (key: string) => axiosResponse.headers[key.toLowerCase()] || null
        },
        json: async () => axiosResponse.data,
        text: async () => typeof axiosResponse.data === 'string' ? axiosResponse.data : JSON.stringify(axiosResponse.data)
      };
      
      logInfo('📡 DGFT API Response received', {
        operation: 'fetchORMDetails',
        requestId,
        statusCode: Number(response.status),
        statusText: response.statusText,
        durationMs: `${duration}ms`,
        responseSize,
        ok: response.ok,
        isIPWhitelistError: response.status === 403,
        isAuthError: response.status === 401
      });
    } catch (axiosError: any) {
      duration = Date.now() - startTime;
      responseSize = 'unknown';
      
      if (axiosError.response) {
        response = {
          status: axiosError.response.status,
          statusText: axiosError.response.statusText || 'Error',
          ok: false,
          headers: {
            get: (key: string) => axiosError.response?.headers[key.toLowerCase()] || null
          },
          json: async () => axiosError.response?.data || {},
          text: async () => typeof axiosError.response?.data === 'string' 
            ? axiosError.response.data 
            : JSON.stringify(axiosError.response?.data || {})
        };
      } else {
        throw new Error(`Network error: ${axiosError.message || 'Unknown error'}`);
      }
    }
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      
      logInfo('🚨 DGFT API Error Response', {
        requestId,
        statusCode: response.status,
        statusText: response.statusText,
        errorData: JSON.stringify(errorData)
      });
      
      const errorCode = errorData.errorCode || errorData.error || String(response.status);
      const errorDescription = errorData.errorDescription || errorData.message || response.statusText;
      
      if (response.status === 403) {
        const ipWhitelistMessage = `IP Whitelisting Required: ${errorDescription}. Your server IP address needs to be whitelisted in the DGFT portal. Please contact your DGFT administrator to add your server IP address.`;
        logApiError('fetchORMDetails', {
          response: { data: errorData },
          message: ipWhitelistMessage,
          statusCode: response.status
        }, requestId, url, Number(response.status));
        const error = new Error(ipWhitelistMessage);
        (error as any).statusCode = 403;
        (error as any).isIPWhitelistError = true;
        throw error;
      }
      
      if (response.status === 401) {
        const authMessage = `Authentication Failed: ${errorDescription}. Please verify your client_id, client_secret, and x-api-key credentials.`;
        logApiError('fetchORMDetails', {
          response: { data: errorData },
          message: authMessage,
          statusCode: response.status
        }, requestId, url, Number(response.status));
        const error = new Error(authMessage);
        (error as any).statusCode = 401;
        (error as any).isAuthError = true;
        throw error;
      }
      
      const errorMessage = `DGFT API Error (${errorCode}): ${errorDescription}`;
      logApiError('fetchORMDetails', {
        response: { data: errorData },
        message: errorMessage,
        statusCode: response.status
      }, requestId, url, Number(response.status));
      const error = new Error(errorMessage);
      (error as any).statusCode = response.status;
      throw error;
    }
    
    const encryptedResponse: EncryptedPayload = await response.json();
    
    logInfo('🔓 Decrypting ORM response', { requestId });
    
    // Lazy-load crypto function to prevent FUNCTION_INVOCATION_FAILED
    const { decryptResponse } = await import('../lib/dgftCrypto');
    
    const decryptedData = await decryptResponse(
      encryptedResponse.data,
      encryptedResponse.sign,
      secretKey,
      credentials.dgftPublicKey,
      credentials.userPrivateKey
    ) as ORMDetailsResponse;
    
    logApiResponse('fetchORMDetails', Number(response.status), duration, {
      recordCount: decryptedData.ormResplst?.length || 0,
      hasRecords: (decryptedData.ormResplst?.length || 0) > 0
    }, requestId);
    
    return decryptedData;
  } catch (error: any) {
    const duration = Date.now() - startTime;
    const dgftError = parseError(error);
    logApiError('fetchORMDetails', error, requestId, url, Number(error?.response?.status || error?.statusCode || 0));
    throw new Error(`Failed to fetch ORM details: ${dgftError.message} (${dgftError.code})`);
  }
}

/**
 * Push IRM to Generate eBRC
 */
export async function pushIRMToGenEBRC(
  accessToken: string,
  credentials: DGFTCredentials,
  request: PushIRMToGenEBRCRequest
): Promise<PushIRMToGenEBRCResponse> {
  const startTime = Date.now();
  const requestId = request.requestId || `EBRC-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const url = `${API_BASE_URL}/pushIRMToGenEBRC`;
  
  // Lazy-load crypto function to prevent FUNCTION_INVOCATION_FAILED
  const { prepareEncryptedPayload } = await import('../lib/dgftCrypto');
  
  const { payload, secretVal, secretKey } = await prepareEncryptedPayload(
    request,
    credentials.userPrivateKey,
    credentials.dgftPublicKey
  );
  
  logInfo('🔐 Encryption Details for eBRC Generation', {
    requestId: request.requestId,
    secretKeyLength: secretKey.length,
    secretValLength: secretVal.length,
    payloadDataLength: payload.data.length,
    signatureLength: payload.sign.length,
    hasSecretKey: !!secretKey,
    hasSecretVal: !!secretVal,
    recordCount: request.recordResCount
  }  );
  
  // Generate messageID per DGFT API requirement (Section 3, Step 6)
  const messageID = generateMessageID();
  
  // Validate messageID was generated correctly
  if (!messageID || messageID.trim().length === 0) {
    const error = new Error('messageID generation failed');
    logApiError('pushIRMToGenEBRC', error, requestId, url, 500);
    throw error;
  }
  
  logInfo('🔍 messageID Generated', {
    requestId: request.requestId,
    messageID,
    hasMessageID: !!messageID,
    messageIDLength: messageID.length
  });
  
  logApiRequest('pushIRMToGenEBRC', url, 'POST', {
    'Content-Type': 'application/json',
    'accessToken': '[REDACTED]',
    'client_id': credentials.clientId,
    'secretVal': '[REDACTED]',
    'messageID': messageID
  }, {
    data: '[ENCRYPTED]',
    sign: '[ENCRYPTED]'
  }, requestId);
  
  logInfo('📋 eBRC Generation Request Details', {
    requestId: request.requestId,
    iecNumber: request.iecNumber,
    recordCount: request.recordResCount,
    uploadType: request.uploadType,
    declarationFlag: request.decalarationFlag
  });
  
  try {
    logInfo('🚀 Sending eBRC generation request to DGFT', {
      requestId: request.requestId,
      url,
      timestamp: new Date().toISOString()
    });
    
    // Per DGFT API Documentation Section 5.4 & Section 3 Step 6 - same header format as fetchIRMDetails
    // Headers: Content-Type, accessToken, client_id, secretVal, messageID (NO x-api-key)
    
    // Explicitly verify messageID exists
    if (!messageID || typeof messageID !== 'string' || messageID.trim().length === 0) {
      const error = new Error(`messageID is invalid: ${messageID}`);
      logApiError('pushIRMToGenEBRC', error, requestId, url, 500);
      throw error;
    }
    
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'accessToken': accessToken,
        'client_id': credentials.clientId,
      'secretVal': secretVal,
      'messageID': messageID
    };
    
    // Explicitly ensure messageID is in headers (fallback)
    if (!('messageID' in headers) || !headers['messageID']) {
      headers['messageID'] = messageID;
      logInfo('⚠️ messageID was missing, added as fallback', { requestId: request.requestId, messageID });
    }
    
    // Validate all required headers are present
    const requiredHeaders = ['Content-Type', 'accessToken', 'client_id', 'secretVal', 'messageID'];
    const missingHeaders = requiredHeaders.filter(h => !(h in headers) || !headers[h] || headers[h].trim().length === 0);
    if (missingHeaders.length > 0) {
      const error = new Error(`Missing required headers: ${missingHeaders.join(', ')}`);
      logApiError('pushIRMToGenEBRC', error, requestId, url, 500);
      throw error;
    }
    
    // Use axios to preserve exact header case
    const axiosHeaders = {
      'Content-Type': 'application/json',
      'accessToken': accessToken,
      'client_id': credentials.clientId,
      'secretVal': secretVal,
      'x-api-key': credentials.xApiKey,
      'messageID': messageID
    };
    
    let response: any;
    let duration: number;
    let responseSize: string;
    
    try {
      const startFetch = Date.now();
      const axiosResponse = await axios.post(url, payload, {
        headers: axiosHeaders,
        timeout: 30000,
        validateStatus: () => true
      });
      
      duration = Date.now() - startFetch;
      responseSize = axiosResponse.headers['content-length'] || 'unknown';
      
      response = {
        status: axiosResponse.status,
        statusText: axiosResponse.statusText,
        ok: axiosResponse.status >= 200 && axiosResponse.status < 300,
        headers: {
          get: (key: string) => axiosResponse.headers[key.toLowerCase()] || null
        },
        json: async () => axiosResponse.data,
        text: async () => typeof axiosResponse.data === 'string' ? axiosResponse.data : JSON.stringify(axiosResponse.data)
      };
      
      logInfo('📡 DGFT API Response received', {
        operation: 'pushIRMToGenEBRC',
        requestId: request.requestId,
        statusCode: Number(response.status),
        statusText: response.statusText,
        durationMs: `${duration}ms`,
        responseSize,
        ok: response.ok,
        isIPWhitelistError: response.status === 403,
        isAuthError: response.status === 401
      });
    } catch (axiosError: any) {
      duration = Date.now() - startTime;
      responseSize = 'unknown';
      
      if (axiosError.response) {
        response = {
          status: axiosError.response.status,
          statusText: axiosError.response.statusText || 'Error',
          ok: false,
          headers: {
            get: (key: string) => axiosError.response?.headers[key.toLowerCase()] || null
          },
          json: async () => axiosError.response?.data || {},
          text: async () => typeof axiosError.response?.data === 'string' 
            ? axiosError.response.data 
            : JSON.stringify(axiosError.response?.data || {})
        };
      } else {
        throw new Error(`Network error: ${axiosError.message || 'Unknown error'}`);
      }
    }
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      
      logInfo('🚨 DGFT API Error Response', {
        requestId: request.requestId,
        statusCode: response.status,
        statusText: response.statusText,
        errorData: JSON.stringify(errorData)
      });
      
      const errorCode = errorData.errorCode || errorData.error || String(response.status);
      const errorDescription = errorData.errorDescription || errorData.message || response.statusText;
      
      if (response.status === 403) {
        const ipWhitelistMessage = `IP Whitelisting Required: ${errorDescription}. Your server IP address needs to be whitelisted in the DGFT portal. Please contact your DGFT administrator to add your server IP address.`;
        logApiError('pushIRMToGenEBRC', {
          response: { data: errorData },
          message: ipWhitelistMessage,
          statusCode: response.status
        }, requestId, url, Number(response.status));
        const error = new Error(ipWhitelistMessage);
        (error as any).statusCode = 403;
        (error as any).isIPWhitelistError = true;
        throw error;
      }
      
      if (response.status === 401) {
        const authMessage = `Authentication Failed: ${errorDescription}. Please verify your client_id, client_secret, and x-api-key credentials.`;
        logApiError('pushIRMToGenEBRC', {
          response: { data: errorData },
          message: authMessage,
          statusCode: response.status
        }, requestId, url, Number(response.status));
        const error = new Error(authMessage);
        (error as any).statusCode = 401;
        (error as any).isAuthError = true;
        throw error;
      }
      
      const errorMessage = `DGFT API Error (${errorCode}): ${errorDescription}`;
      logApiError('pushIRMToGenEBRC', {
        response: { data: errorData },
        message: errorMessage,
        statusCode: response.status
      }, requestId, url, Number(response.status));
      const error = new Error(errorMessage);
      (error as any).statusCode = response.status;
      throw error;
    }
    
    const encryptedResponse: EncryptedPayload = await response.json();
    
    logInfo('🔓 Decrypting eBRC generation response', { requestId: request.requestId });
    
    // Lazy-load crypto function to prevent FUNCTION_INVOCATION_FAILED
    const { decryptResponse } = await import('../lib/dgftCrypto');
    
    const decryptedData = await decryptResponse(
      encryptedResponse.data,
      encryptedResponse.sign,
      secretKey,
      credentials.dgftPublicKey,
      credentials.userPrivateKey
    ) as PushIRMToGenEBRCResponse;
    
    logApiResponse('pushIRMToGenEBRC', Number(response.status), duration, {
      requestId: decryptedData.requestId,
      dgftAckId: decryptedData.dgftAckId,
      ackStatus: decryptedData.ackStatus,
      recordResCount: decryptedData.recordResCount,
      hasErrors: decryptedData.errorDetails && decryptedData.errorDetails.length > 0
    }, requestId);
    
    logInfo('✅ eBRC generation request successfully sent to DGFT', {
      requestId: decryptedData.requestId,
      dgftAckId: decryptedData.dgftAckId,
      ackStatus: decryptedData.ackStatus,
      timestamp: new Date().toISOString()
    });
    
    return decryptedData;
  } catch (error: any) {
    const duration = Date.now() - startTime;
    const dgftError = parseError(error);
    logApiError('pushIRMToGenEBRC', error, requestId, url, Number(error?.response?.status || error?.statusCode || 0));
    throw new Error(`Failed to push IRM for eBRC generation: ${dgftError.message} (${dgftError.code})`);
  }
}

/**
 * Get Request Status
 */
export async function getRequestStatus(
  accessToken: string,
  credentials: DGFTCredentials,
  request: GetRequestStatusRequest
): Promise<GetRequestStatusResponse> {
  const startTime = Date.now();
  const requestId = `STATUS-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const url = `${API_BASE_URL}/getRequestStatus`;
  
  // Lazy-load crypto function to prevent FUNCTION_INVOCATION_FAILED
  const { prepareEncryptedPayload } = await import('../lib/dgftCrypto');
  
  const { payload, secretVal, secretKey } = await prepareEncryptedPayload(
    request,
    credentials.userPrivateKey,
    credentials.dgftPublicKey
  );
  
  // Generate messageID per DGFT API requirement (Section 3, Step 6)
  const messageID = generateMessageID();
  
  // Validate messageID was generated correctly
  if (!messageID || messageID.trim().length === 0) {
    const error = new Error('messageID generation failed');
    logApiError('getRequestStatus', error, requestId, url, 500);
    throw error;
  }
  
  logInfo('🔍 messageID Generated', {
    requestId,
    messageID,
    hasMessageID: !!messageID,
    messageIDLength: messageID.length
  });
  
  logApiRequest('getRequestStatus', url, 'POST', {
    'Content-Type': 'application/json',
    'accessToken': '[REDACTED]',
    'client_id': credentials.clientId,
    'secretVal': '[REDACTED]',
    'messageID': messageID
  }, {
    data: '[ENCRYPTED]',
    sign: '[ENCRYPTED]'
  }, requestId);
  
  logInfo('📋 Status Request Details', {
    requestId,
    statusRequestId: request.requestId
  });
  
  try {
    // Per DGFT API Documentation Section 5.5 & Section 3 Step 6 - same header format as fetchIRMDetails
    // Headers: Content-Type, accessToken, client_id, secretVal, messageID (NO x-api-key)
    
    // Explicitly verify messageID exists
    if (!messageID || typeof messageID !== 'string' || messageID.trim().length === 0) {
      const error = new Error(`messageID is invalid: ${messageID}`);
      logApiError('getRequestStatus', error, requestId, url, 500);
      throw error;
    }
    
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'accessToken': accessToken,
        'client_id': credentials.clientId,
      'secretVal': secretVal,
      'x-api-key': credentials.xApiKey,
      'messageID': messageID
    };
    
    // Explicitly ensure messageID is in headers (fallback)
    if (!('messageID' in headers) || !headers['messageID']) {
      headers['messageID'] = messageID;
      logInfo('⚠️ messageID was missing, added as fallback', { requestId, messageID });
    }
    
    // Validate all required headers are present
    const requiredHeaders = ['Content-Type', 'accessToken', 'client_id', 'secretVal', 'x-api-key', 'messageID'];
    const missingHeaders = requiredHeaders.filter(h => !(h in headers) || !headers[h] || headers[h].trim().length === 0);
    if (missingHeaders.length > 0) {
      const error = new Error(`Missing required headers: ${missingHeaders.join(', ')}`);
      logApiError('getRequestStatus', error, requestId, url, 500);
      throw error;
    }
    
    // Final verification before fetch
    if (!('messageID' in headers) || !headers['messageID']) {
      headers['messageID'] = messageID;
      logInfo('⚠️ messageID missing before fetch, re-added', { requestId, messageID });
    }
    
    // Log headers validation right before fetch
    logInfo('🔍 Headers Before Fetch', {
      requestId,
      headerKeys: Object.keys(headers),
      headerCount: Object.keys(headers).length,
      hasMessageID: 'messageID' in headers,
      messageIDValue: headers['messageID'],
      messageIDLength: headers['messageID']?.length || 0,
      allRequiredPresent: requiredHeaders.every(h => h in headers && headers[h] && headers[h].trim().length > 0)
    });
    
    // Use axios to preserve exact header case
    const axiosHeaders = {
      'Content-Type': 'application/json',
      'accessToken': accessToken,
      'client_id': credentials.clientId,
      'secretVal': secretVal,
      'x-api-key': credentials.xApiKey,
      'messageID': messageID
    };
    
    let response: any;
    let duration: number;
    let responseSize: string;
    
    try {
      const startFetch = Date.now();
      const axiosResponse = await axios.post(url, payload, {
        headers: axiosHeaders,
        timeout: 30000,
        validateStatus: () => true
      });
      
      duration = Date.now() - startFetch;
      responseSize = axiosResponse.headers['content-length'] || 'unknown';
      
      response = {
        status: axiosResponse.status,
        statusText: axiosResponse.statusText,
        ok: axiosResponse.status >= 200 && axiosResponse.status < 300,
        headers: {
          get: (key: string) => axiosResponse.headers[key.toLowerCase()] || null
        },
        json: async () => axiosResponse.data,
        text: async () => typeof axiosResponse.data === 'string' ? axiosResponse.data : JSON.stringify(axiosResponse.data)
      };
      
      logInfo('📡 DGFT API Response received', {
        operation: 'getRequestStatus',
        requestId,
        statusCode: Number(response.status),
        statusText: response.statusText,
        durationMs: `${duration}ms`,
        responseSize,
        ok: response.ok,
        isIPWhitelistError: response.status === 403,
        isAuthError: response.status === 401
      });
    } catch (axiosError: any) {
      duration = Date.now() - startTime;
      responseSize = 'unknown';
      
      if (axiosError.response) {
        response = {
          status: axiosError.response.status,
          statusText: axiosError.response.statusText || 'Error',
          ok: false,
          headers: {
            get: (key: string) => axiosError.response?.headers[key.toLowerCase()] || null
          },
          json: async () => axiosError.response?.data || {},
          text: async () => typeof axiosError.response?.data === 'string' 
            ? axiosError.response.data 
            : JSON.stringify(axiosError.response?.data || {})
        };
      } else {
        throw new Error(`Network error: ${axiosError.message || 'Unknown error'}`);
      }
    }
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      
      logInfo('🚨 DGFT API Error Response', {
        requestId,
        statusCode: response.status,
        statusText: response.statusText,
        errorData: JSON.stringify(errorData)
      });
      
      const errorCode = errorData.errorCode || errorData.error || String(response.status);
      const errorDescription = errorData.errorDescription || errorData.message || response.statusText;
      
      if (response.status === 403) {
        const ipWhitelistMessage = `IP Whitelisting Required: ${errorDescription}. Your server IP address needs to be whitelisted in the DGFT portal. Please contact your DGFT administrator to add your server IP address.`;
        logApiError('getRequestStatus', {
          response: { data: errorData },
          message: ipWhitelistMessage,
          statusCode: response.status
        }, requestId, url, Number(response.status));
        const error = new Error(ipWhitelistMessage);
        (error as any).statusCode = 403;
        (error as any).isIPWhitelistError = true;
        throw error;
      }
      
      if (response.status === 401) {
        const authMessage = `Authentication Failed: ${errorDescription}. Please verify your client_id, client_secret, and x-api-key credentials.`;
        logApiError('getRequestStatus', {
          response: { data: errorData },
          message: authMessage,
          statusCode: response.status
        }, requestId, url, Number(response.status));
        const error = new Error(authMessage);
        (error as any).statusCode = 401;
        (error as any).isAuthError = true;
        throw error;
      }
      
      const errorMessage = `DGFT API Error (${errorCode}): ${errorDescription}`;
      logApiError('getRequestStatus', {
        response: { data: errorData },
        message: errorMessage,
        statusCode: response.status
      }, requestId, url, Number(response.status));
      const error = new Error(errorMessage);
      (error as any).statusCode = response.status;
      throw error;
    }
    
    const encryptedResponse: EncryptedPayload = await response.json();
    
    logInfo('🔓 Decrypting status response', { requestId });
    
    // Lazy-load crypto function to prevent FUNCTION_INVOCATION_FAILED
    const { decryptResponse } = await import('../lib/dgftCrypto');
    
    const decryptedData = await decryptResponse(
      encryptedResponse.data,
      encryptedResponse.sign,
      secretKey,
      credentials.dgftPublicKey,
      credentials.userPrivateKey
    ) as GetRequestStatusResponse;
    
    logApiResponse('getRequestStatus', Number(response.status), duration, {
      requestId: decryptedData.requestId,
      processingStatus: decryptedData.processingStatus,
      recordProCount: decryptedData.recordProCount,
      recordFailCount: decryptedData.recordFailCount,
      totalRecords: decryptedData.recordResCount
    }, requestId);
    
    return decryptedData;
  } catch (error: any) {
    const duration = Date.now() - startTime;
    const dgftError = parseError(error);
    logApiError('getRequestStatus', error, requestId, url, Number(error?.response?.status || error?.statusCode || 0));
    throw new Error(`Failed to get request status: ${dgftError.message} (${dgftError.code})`);
  }
}


