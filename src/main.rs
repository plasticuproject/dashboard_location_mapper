use maxminddb::geoip2;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::hash::Hash;
use std::net::IpAddr;

/// Represents the structure of threat sources loaded from a JSON file.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
struct ThreatSources {
    Count: Vec<u32>,
    Source: Vec<String>,
}

/// Holds aggregated data for cities, including the name and total count of threats.
#[derive(Default)]
struct CityData {
    city_name: String,
    country_name: String,
    total_count: u32,
}

/// A struct to use as a key for locations in the `HashMap`, representing latitude and longitude.
#[derive(Hash, PartialEq, Eq)]
struct LocationKey {
    lat: String,
    lon: String,
}

/// The main entry point for the IP geolocation aggregation tool.
///
/// This function performs several key operations:
/// 1. Reads a list of source IP addresses and their associated threat counts
///    from a JSON file named `threat_sources.json`.
/// 2. Uses the `maxminddb` crate to lookup geographical locations (city, country,
///    latitude, and longitude) for each IP address using the `MaxMind GeoLite2`
///    City database (`city.mmdb`).
/// 3. Aggregates threat counts by city, summing counts for IPs mapping to the
///    same city location.
/// 4. Outputs the aggregated data to a CSV file named "locations.csv", with
///    each row representing a unique city location and including the city name,
///    country name, total aggregated count, latitude, and longitude.
///
/// IPs with indeterminable geographical locations or missing city names in the
/// database are skipped.
///
/// Error Handling:
/// - Propagates errors using Rust's `Result` type for graceful error handling.
/// - Failures to open files or parse JSON content result in program termination
///   with an appropriate error message.
///
/// Note:
/// This function expects `threat_sources.json` and `city.mmdb` to be present and
/// accessible in the working directory before running.
fn main() -> Result<(), Box<dyn Error>> {
    // Open and read the JSON file containing the threat sources.
    let file = File::open("threat_sources.json")?;
    let json: Value = serde_json::from_reader(file)?;
    let threat_sources: ThreatSources = serde_json::from_value(json["Threat Sources"].clone())?;

    // Open the MaxMind DB for IP geolocation lookup.
    let reader = maxminddb::Reader::open_readfile("geoip2/city.mmdb")?;

    // Initialize the CSV writer to write the aggregated location data.
    let mut wtr = csv::Writer::from_path("locations.csv")?;
    wtr.write_record(["City Name", "Country Name", "Count", "Lat", "Lon"])?;

    // Use a HashMap to aggregate counts by city location (lat, lon).
    let mut locations: HashMap<LocationKey, CityData> = HashMap::new();

    // Iterate through each source IP to lookup its geographical location and aggregate counts.
    for (i, ip_str) in threat_sources.Source.iter().enumerate() {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            if let Ok(city) = reader.lookup::<geoip2::City>(ip) {
                if let Some(city_name) = city
                    .city
                    .and_then(|c| c.names)
                    .and_then(|n| n.get("en").copied())
                {
                    if let Some(country_name) = city
                        .country
                        .and_then(|c| c.names)
                        .and_then(|n| n.get("en").copied())
                    {
                        if let Some(location) = city.location {
                            if let (Some(lat), Some(lon)) = (location.latitude, location.longitude)
                            {
                                // Round lat and lon to 5 decimal places and use as hashable key.
                                let key = LocationKey {
                                    lat: format!("{lat:.5}"),
                                    lon: format!("{lon:.5}"),
                                };
                                let count = threat_sources.Count[i];
                                // Aggregate counts for each unique location.
                                locations
                                    .entry(key)
                                    .and_modify(|e| e.total_count += count)
                                    .or_insert_with(|| CityData {
                                        city_name: city_name.to_string(),
                                        country_name: country_name.to_string(),
                                        total_count: count,
                                    });
                            }
                        }
                    }
                }
            }
        }
    }

    // Write the aggregated data to the CSV file.
    for (key, data) in locations {
        wtr.write_record([
            &data.city_name,
            &data.country_name,
            &data.total_count.to_string(),
            &key.lat,
            &key.lon,
        ])?;
    }

    wtr.flush()?;
    Ok(())
}
