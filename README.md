[![Rust 1.80](https://img.shields.io/badge/rust-1.80+-red.svg)](https://www.rust-lang.org/tools/install)
[![Lint Build Release](https://github.com/plasticuproject/dashboard_location_mapper/actions/workflows/rust.yml/badge.svg)](https://github.com/plasticuproject/dashboard_location_mapper/actions/workflows/rust.yml)
![Maintenance](https://img.shields.io/badge/maintenance-actively--developed-brightgreen.svg)

# Dashboard Location Mapper

The `dashboard_location_mapper` is a Rust-based tool designed to process a list of source IP addresses, look up their geographical locations using the MaxMind GeoLite2 City database, and aggregate threat counts by city. The aggregated data is then output to a CSV file, making it easy to analyze or visualize the distribution of threat sources geographically.


## Features
- **IP Geolocation Lookup**: Utilizes the `maxminddb` crate to query geographical locations for IP addresses.
- **Data Aggregation**: Aggregates threat counts by city location based on latitude and longitude.
- **CSV Output**: Outputs the aggregated data to a CSV file with fields for city name, total count, latitude, and longitude.

## Getting Started

### Prerequisites
- Rust 1.80 or later
- Cargo for managing Rust packages
- MaxMind GeoLite2 City Database: Download the GeoLite2 City database in MMDB format from [MaxMind](https://dev.maxmind.com/geoip/geoip2/geolite2/). You will need to create a free account to access the database.

### Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/plasticuproject/dashboard_location_mapper.git
   ```

2. Navigate to the project directory:

   ```sh
   cd dashboard_location_mapper
   ```

3. Build the project:

   ```sh
   cargo build --release
   ```

### Configuration

- Input JSON (`threat_sources.json`): Should contain a JSON object with two arrays, Count and Source, representing the threat counts and their corresponding source IP addresses.
- GeoLite2 City Database (`city.mmdb`): Ensure this file is placed in the root `/geoip2` directory of the project or modify the path in the source code accordingly.

### Usage

   ```sh
   cargo run
   ```

Or just execute the pre-built binary in the directory where you want your output files to reside.

   ```sh
   ./dashboard_location_mapper
   ```

After running, check the output `locations.csv` file in the project or binary directory for the aggregated data.
```
