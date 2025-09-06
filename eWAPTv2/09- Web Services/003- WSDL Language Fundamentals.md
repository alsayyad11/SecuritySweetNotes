
![d](https://github.com/user-attachments/assets/b4b6692b-aaf2-4d9a-a1a9-aec57c5cc456)

## **1. Intro to WSDL**

<img width="1424" height="569" alt="c" src="https://github.com/user-attachments/assets/86977ab7-99c2-472a-96d0-ff51d29c1952" />


**WSDL (Web Services Description Language)** is an **XML-based language** used to describe the functionality and interface of a web service. It is essentially a **contract** between a service provider and a client (consumer), specifying exactly how the web service can be accessed and used.

* **Purpose:**

  * Define the **operations** the service provides.
  * Specify **input and output parameters** for each operation.
  * Define **fault messages** for errors.
  * Specify the **protocol** and message formats used.

* **Usage:**
  WSDL is commonly used in combination with **SOAP (Simple Object Access Protocol)** to define SOAP-based web services.

**Example:**
Suppose a SOAP web service provides weather data:

| Operation        | Input         | Output              |
| ---------------- | ------------- | ------------------- |
| `GetTemperature` | city (string) | temperature (float) |
| `GetHumidity`    | city (string) | humidity (float)    |

This contract ensures that the client knows how to send a request and what response to expect.

---

## **2. WSDL Versions**

* **WSDL 1.1:** Original version, widely used.
* **WSDL 2.0:** Latest version, introduces improvements like replacing `<portType>` with `<interface>`.

**Key distinction in WSDL documents:**

1. **Abstract definitions:**
   Describe *what the service does* — the operations, inputs, outputs, and fault messages.
   Example: `Operation GetTemperature(city) → temperature`

2. **Concrete definitions:**
   Describe *how the service communicates* and where it is hosted — protocols, bindings, and endpoint URLs.
   Example: `SOAP over HTTP, endpoint URL: https://api.weather.com/service`

---

## **3. WSDL Document Components**

### **a. Types**

The `<types>` section defines **data types** used in the service using XML Schema Definitions (XSD). This ensures consistent understanding of data structure.

```xml
<xsd:element name="city" type="xsd:string"/>
<xsd:element name="temperature" type="xsd:float"/>
```

---

### **b. Message**

The `<message>` element defines the **structure of messages** exchanged between the client and the service. Each message can have multiple parts, referencing types in `<types>`.

```xml
<message name="GetTemperatureRequest">
  <part name="city" type="xsd:string"/>
</message>
<message name="GetTemperatureResponse">
  <part name="temperature" type="xsd:float"/>
</message>
```

---

<img width="1421" height="580" alt="S" src="https://github.com/user-attachments/assets/3090d7c6-dfde-4ce1-b048-a270e7aba783" />


### **c. PortType (WSDL 1.1)**

The `<portType>` element defines **available operations** and their input/output messages.

```xml
<portType name="WeatherPortType">
  <operation name="GetTemperature">
    <input message="tns:GetTemperatureRequest"/>
    <output message="tns:GetTemperatureResponse"/>
  </operation>
</portType>
```

---

### **d. Binding**

The `<binding>` element specifies **how operations are bound to a protocol**, e.g., SOAP over HTTP. It defines message encoding and transport.

```xml
<binding name="WeatherBinding" type="tns:WeatherPortType">
  <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
</binding>
```

---

### **e. Service**

The `<service>` element defines the service itself and its **endpoint URL**, where clients can access it.

```xml
<service name="WeatherService">
  <port name="WeatherPort" binding="tns:WeatherBinding">
    <soap:address location="https://api.weather.com/service"/>
  </port>
</service>
```

---

### **f. Interface (WSDL 2.0)**

* WSDL 2.0 replaces `<portType>` with `<interface>`.
* Points to **schema elements** instead of messages.
* Defines operations and message types for client-service interaction.

```xml
<interface name="WeatherInterface">
  <operation name="GetTemperature"/>
</interface>
```

---

## **4. Client-Service Interaction**

1. Client reads the WSDL file to understand available operations.
2. Constructs a SOAP request using specified **message formats**.
3. Service processes the request and returns a SOAP response.

**Example SOAP Request:**

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:web="http://api.weather.com/webservice">
   <soapenv:Header/>
   <soapenv:Body>
      <web:GetTemperature>
         <web:city>Cairo</web:city>
      </web:GetTemperature>
   </soapenv:Body>
</soapenv:Envelope>
```

**Response:**

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:web="http://api.weather.com/webservice">
   <soapenv:Header/>
   <soapenv:Body>
      <web:GetTemperatureResponse>
         <web:temperature>34.5</web:temperature>
      </web:GetTemperatureResponse>
   </soapenv:Body>
</soapenv:Envelope>
```

---

## **5. Web Service Security Testing**

**Objective:** Evaluate security to identify vulnerabilities or threats that could compromise **confidentiality, integrity, or availability** of the service.

* Web services are common targets due to internet exposure.

---

### **a. Information Gathering**

* Identify SOAP services and their WSDL files.
* Gather:

  * Endpoints
  * Operations
  * Input/output data
  * Authentication and authorization mechanisms

**Example:**
WSDL URL: `https://api.weather.com/service?wsdl`
Auth: API key in SOAP header

---

### **b. Threat Modeling**

* Identify potential security threats:

  * Unauthorized access
  * Data injection
  * XML-based attacks like **XXE (XML External Entity Injection)**

---

### **c. Authentication & Authorization Testing**

* Test authentication (username/password, tokens)
* Verify authorized users can access only permitted operations.

---

### **d. Input Validation Testing**

* Check for:

  * SQL Injection
  * Cross-Site Scripting (XSS)
  * XML Injection

**Example Malicious Input:**

```xml
<city><script>alert('XSS')</script></city>
```

Server must **sanitize or reject** the input.

---

### **e. SOAP Web Service Security Testing Methodology**

1. Identify SOAP service and endpoints.
2. Enumerate WSDL file.
3. Invoke hidden/undocumented methods.
4. Bypass SOAP body restrictions.
5. Test input validation vulnerabilities.

---

### **f. WSDL Disclosure & Method Enumeration**

* Access WSDL to get:

  * Full operations list
  * Input/output parameters
  * Message syntax

* Discovery methods:

  * Append `?wsdl` or `.wsdl` to service URL
  * Example: `https://api.weather.com/service?wsdl`

---

### **g. Practical Example**

* Service: Weather SOAP API
* Steps:

  1. Open WSDL → Check operations (`GetTemperature`, `GetHumidity`)
  2. Construct valid SOAP requests
  3. Send requests → Receive responses
  4. Perform security tests (malformed inputs, bypasses)

---
