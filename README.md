# 🌐 IP Address Validator & Subnet Calculator — Computer Networks Project

An interactive, full-stack **Computer Networks (CN)** laboratory tool for real-time **IPv4 & IPv6 address validation**, **classful classification**, **RFC 1918 private vs. public analysis**, **CIDR subnet calculation**, **binary conversion**, and **IPv6 topology inspection**.

Designed with a modern, pastel-themed interface featuring glassmorphic cards, responsive layouts, dynamic animations, and an educational Computer Networks theory guide.

---

## 📸 Features & Visual Design

- **Pastel Glassmorphism Theme**: Soft gradient background (`#fdf4ff` to `#ede9fe` to `#f0f9ff`) with floating bokeh orbs and rounded translucent cards.
- **Dynamic Real-Time Validation**:
  - Green success banner for valid addresses with dynamic status description.
  - Red alert banner for invalid IPs with clear error diagnostic explanations.
- **IPv4 Address Analysis**:
  - **Hero Overview**: Large highlighted IP, IP version badge, Class badge, Special type badge, RFC 1918 indicator, Internet Routability badge.
  - **General Info**: IP address, Version, Total bits (32 bits), Octet count (4), Separator (`Dot .`).
  - **IP Class Detection**: Classes A, B, C, D (Multicast), and E (Experimental), address ranges, network bits, host bits, leading bits (`0`, `10`, `110`, `1110`, `1111`), and an interactive highlighted 5-class segment track.
  - **Subnet & CIDR**: Default subnet mask, CIDR prefix, network address, broadcast address, first usable host, last usable host, maximum usable hosts ($2^h - 2$), and dynamic Network vs. Host bit distribution progress bar.
  - **Visibility & Scope**: Public, Private, Loopback, Link-Local (APIPA), and Broadcast with animated pulsing status indicators, RFC 1918 private range specifications, and routability checks.
  - **Binary Representation**: 4 octet boxes displaying each byte in 8-bit binary and decimal, plus full 32-bit dot-separated binary string.
- **IPv6 Address Analysis**:
  - **Hero Overview**: Compressed format, IPv6 badge, Address Type badge, Scope badge.
  - **General Info**: 128 total bits, 8 groups of 16-bit hexadecimal, compression indicator, typical prefix length (`/64`), and reachability scope.
  - **Address Classification**: Global Unicast, Link-Local Unicast (`fe80::/10`), Unique Local Unicast ULA (`fc00::/7` / `fd00::/8`), Multicast (`ff00::/8`), Loopback (`::1`), IPv4-Mapped IPv6 (`::ffff:0:0/96`), and 6to4/Teredo tunneling.
  - **Address Forms**: Compressed vs. full expanded 8-group representation and full 128-bit grouped binary.
  - **16-bit Hex Groups**: Interactive 8-block grid displaying each group in uppercase hexadecimal and spaced 4-bit binary nibbles.
  - **Scope Hierarchy**: Reachability indicators highlighting `Node`, `Link`, `Site`, `Organization/Site`, or `Global`.
- **CIDR Subnet Calculator Tab**:
  - Calculate subnet masks, wildcard masks, network & broadcast boundaries, host capacity, borrowed subnet bits, and possible subnets for any CIDR notation (e.g. `192.168.1.0/26`).
  - Quick example chips for common prefixes (`/8`, `/20`, `/24`, `/26`, `/28`, `/30`).
- **CN Theory Tab**:
  - 10 structured reference modules detailing IPv4/IPv6 fundamentals, classful vs CIDR subnetting, RFC 1918 ranges, bitwise masking, and Client-Server Application Layer architecture.
- **Recent Validations History**:
  - Stored in browser `localStorage`, displays recent lookups with status icons and version badges, one-click re-validation, and clear history option.

---

## 🛠️ Technology Stack

- **Backend**: Pure Python 3 — **Zero external dependencies** (uses built-in standard library: `http.server`, `json`, `ipaddress`, `math`, `re`)
- **Frontend**: HTML5, Modern CSS3 (Obsidian Dark Glassmorphism, Flexbox, CSS Grid), Vanilla JavaScript (ES6+ Fetch API)
- **Typography**: Google Fonts — *Poppins* (headings & UI) & *JetBrains Mono* (IP addresses & binary)

---

## 📁 Project Structure

```
d:\Validation of IP\
├── app.py                  # Pure Python HTTP server & REST API (Zero external dependencies)
├── validator.py            # Core Computer Networks validation & calculation engine
├── requirements.txt        # Notes zero external dependencies needed
├── README.md               # Project documentation & CN curriculum reference
└── templates/
    └── index.html          # Responsive single-page application (HTML, CSS, JS)
```

---

## 🚀 How to Run the Project

### 1. Prerequisites
Make sure Python 3.8+ is installed on your system. No `pip install` or virtual environments required!

### 2. Start the Server
```bash
python app.py
```

### 3. Open in Browser
Visit **[`http://localhost:5000`](http://localhost:5000)** in any modern web browser.

### 3. Run the Flask Server
```bash
python app.py
```

### 4. Open in Browser
Visit `http://localhost:5000` in your web browser.

---

## 📡 REST API Endpoints

### 1. `POST /api/validate`
Validates and analyzes any IPv4 or IPv6 address.
- **Request Body**:
  ```json
  { "ip": "10.0.0.1" }
  ```
- **Response**: Full validation object including class, binary representation, subnet information, and visibility status.

### 2. `POST /api/subnet`
Calculates subnet parameters for CIDR notation.
- **Request Body**:
  ```json
  { "cidr": "192.168.1.0/26" }
  ```
- **Response**: Subnet mask, wildcard mask, network address, broadcast address, host range, usable hosts count, borrowed bits, and binary masks.

### 3. `GET /api/examples`
Returns pre-configured networking examples for quick interactive testing.

### 4. `GET /api/health`
Health check endpoint reporting API status and server timestamp.

---

## 🎓 Computer Networks Concepts Demonstrated

1. **OSI Layer 3 (Network Layer)**: Logical IP addressing, packet routing boundaries, hierarchical address delegation.
2. **OSI Layer 7 (Application Layer)**: Client-Server communication using HTTP protocol and JSON payloads.
3. **Classful Addressing (RFC 791)**: Octet boundary divisions into Classes A, B, C, D, and E based on high-order leading bits.
4. **Classless Inter-Domain Routing (CIDR, RFC 4632)**: Variable-length subnet masks (VLSM), prefix lengths, bit borrowing, host capacity calculation ($2^{\text{host bits}} - 2$).
5. **Private Addressing (RFC 1918)**: Distinguishing non-routable intranet spaces from global Internet-routable public addresses.
6. **Next-Generation Addressing (IPv6, RFC 8200)**: 128-bit address space, hexadecimal notation, zero-compression (`::`), address scopes (Node, Link, Site, Global), and transitional IPv4-mapped formatting.

