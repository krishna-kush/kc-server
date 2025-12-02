/// Comprehensive analytics endpoints for dashboard insights
use actix_web::{web, HttpResponse, Error};
use mongodb::{bson::doc, Database};
use chrono::{Utc, Duration, Datelike};
use serde::Serialize;
use std::collections::HashMap;

use crate::models::{VerificationAttempt, License, Binary};

/// Comprehensive analytics response
#[derive(Debug, Serialize)]
pub struct AnalyticsResponse {
    pub key_metrics: KeyMetrics,
    pub time_series: TimeSeriesData,
    pub hourly_activity: Vec<HourlyActivity>,
    pub license_status: LicenseStatusDistribution,
    pub top_binaries: Vec<TopBinary>,
    pub geographic_distribution: Vec<GeographicData>,
    pub recent_activity: RecentActivitySummary,
}

#[derive(Debug, Serialize)]
pub struct KeyMetrics {
    pub total_verifications: i64,
    pub success_rate: f64,
    pub unique_machines: i64,
    pub avg_response_time_ms: f64,
    pub growth_rate: f64,
}

#[derive(Debug, Serialize)]
pub struct TimeSeriesData {
    pub daily: Vec<TimeSeriesPoint>,
    pub monthly: Vec<TimeSeriesPoint>,
}

#[derive(Debug, Serialize)]
pub struct TimeSeriesPoint {
    pub date: String,
    pub verifications: i64,
    pub successes: i64,
    pub failures: i64,
}

#[derive(Debug, Serialize)]
pub struct HourlyActivity {
    pub hour: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct LicenseStatusDistribution {
    pub active: i64,
    pub revoked: i64,
    pub expired: i64,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct TopBinary {
    pub binary_id: String,
    pub name: String,
    pub executions: i64,
    pub unique_machines: i64,
}

#[derive(Debug, Serialize)]
pub struct GeographicData {
    pub country: String,
    pub count: i64,
    pub percentage: f64,
}

#[derive(Debug, Serialize)]
pub struct RecentActivitySummary {
    pub verifications_last_24h: i64,
    pub verifications_last_7d: i64,
    pub verifications_last_30d: i64,
}

/// Get comprehensive analytics data
/// GET /api/v1/analytics
pub async fn get_analytics(
    db: web::Data<Database>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    let uid = user_id.into_inner();
    let license_collection = db.collection::<License>("licenses");
    let attempt_collection = db.collection::<VerificationAttempt>("verification_attempts");
    let binary_collection = db.collection::<Binary>("binaries");

    // Fetch user's binary IDs
    let mut binary_cursor = binary_collection
        .find(doc! { "user_id": &uid })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
    
    let mut user_binary_ids = Vec::new();
    use futures::stream::StreamExt;
    while let Some(doc) = binary_cursor.next().await {
        if let Ok(binary) = doc {
            user_binary_ids.push(binary.binary_id);
        }
    }
    
    let verification_filter = doc! { "binary_id": { "$in": &user_binary_ids } };

    // Fetch all data in parallel (using tokio::join!)
    let (
        total_verifications,
        successful_verifications,
        unique_machines,
        license_counts,
        hourly_data,
        daily_data,
        top_binaries_data,
        geo_data,
        recent_activity,
    ) = tokio::join!(
        get_total_verifications(&attempt_collection, verification_filter.clone()),
        get_successful_verifications(&attempt_collection, verification_filter.clone()),
        get_unique_machines(&attempt_collection, verification_filter.clone()),
        get_license_counts(&license_collection, uid),
        get_hourly_activity(&attempt_collection, verification_filter.clone()),
        get_daily_time_series(&attempt_collection, verification_filter.clone()),
        get_top_binaries(&attempt_collection, &binary_collection, verification_filter.clone()),
        get_geographic_distribution(&attempt_collection, verification_filter.clone()),
        get_recent_activity(&attempt_collection, verification_filter.clone()),
    );

    let total_verifications = total_verifications?;
    let successful_verifications = successful_verifications?;
    let unique_machines = unique_machines?;
    let (active_licenses, revoked_licenses, expired_licenses, total_licenses) = license_counts?;
    let hourly_activity = hourly_data?;
    let (daily_series, monthly_series) = daily_data?;
    let top_binaries = top_binaries_data?;
    let geographic_distribution = geo_data?;
    let (last_24h, last_7d, last_30d) = recent_activity?;

    // Calculate success rate
    let success_rate = if total_verifications > 0 {
        (successful_verifications as f64 / total_verifications as f64 * 100.0).round() / 10.0 * 10.0
    } else {
        0.0
    };

    // Calculate growth rate (compare last 7 days vs previous 7 days)
    let now = Utc::now();
    let last_7d_start = now - Duration::days(7);
    let prev_7d_start = now - Duration::days(14);
    let prev_7d_end = now - Duration::days(7);

    let mut last_week_filter = verification_filter.clone();
    last_week_filter.insert("timestamp", doc! {
        "$gte": last_7d_start.to_rfc3339(),
        "$lt": now.to_rfc3339(),
    });
    
    let last_week_count = attempt_collection
        .count_documents(last_week_filter)
        .await
        .unwrap_or(0);

    let mut prev_week_filter = verification_filter.clone();
    prev_week_filter.insert("timestamp", doc! {
        "$gte": prev_7d_start.to_rfc3339(),
        "$lt": prev_7d_end.to_rfc3339(),
    });

    let prev_week_count = attempt_collection
        .count_documents(prev_week_filter)
        .await
        .unwrap_or(0);

    let growth_rate = if prev_week_count > 0 {
        ((last_week_count as f64 - prev_week_count as f64) / prev_week_count as f64 * 100.0).round() / 10.0 * 10.0
    } else {
        0.0
    };

    // Mock average response time for now (would need to track in verification attempts)
    let avg_response_time_ms = 24.0;

    let response = AnalyticsResponse {
        key_metrics: KeyMetrics {
            total_verifications,
            success_rate,
            unique_machines,
            avg_response_time_ms,
            growth_rate,
        },
        time_series: TimeSeriesData {
            daily: daily_series,
            monthly: monthly_series,
        },
        hourly_activity,
        license_status: LicenseStatusDistribution {
            active: active_licenses,
            revoked: revoked_licenses,
            expired: expired_licenses,
            total: total_licenses,
        },
        top_binaries,
        geographic_distribution,
        recent_activity: RecentActivitySummary {
            verifications_last_24h: last_24h,
            verifications_last_7d: last_7d,
            verifications_last_30d: last_30d,
        },
    };

    Ok(HttpResponse::Ok().json(response))
}

// Helper functions

async fn get_total_verifications(
    collection: &mongodb::Collection<VerificationAttempt>,
    filter: mongodb::bson::Document,
) -> Result<i64, Error> {
    collection
        .count_documents(filter)
        .await
        .map(|c| c as i64)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))
}

async fn get_successful_verifications(
    collection: &mongodb::Collection<VerificationAttempt>,
    mut filter: mongodb::bson::Document,
) -> Result<i64, Error> {
    filter.insert("success", true);
    collection
        .count_documents(filter)
        .await
        .map(|c| c as i64)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))
}

async fn get_unique_machines(
    collection: &mongodb::Collection<VerificationAttempt>,
    filter: mongodb::bson::Document,
) -> Result<i64, Error> {
    let pipeline = vec![
        doc! { "$match": filter },
        doc! {
            "$group": {
                "_id": "$machine_fingerprint"
            }
        },
        doc! {
            "$count": "count"
        }
    ];

    let mut cursor = collection
        .aggregate(pipeline)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;

    use futures::stream::StreamExt;
    if let Some(result) = cursor.next().await {
        let doc = result.map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;
        Ok(doc.get_i32("count").unwrap_or(0) as i64)
    } else {
        Ok(0)
    }
}

async fn get_license_counts(
    collection: &mongodb::Collection<License>,
    user_id: String,
) -> Result<(i64, i64, i64, i64), Error> {
    let total = collection
        .count_documents(doc! { "user_id": &user_id })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))? as i64;

    let active = collection
        .count_documents(doc! { "user_id": &user_id, "revoked": false })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))? as i64;

    let revoked = collection
        .count_documents(doc! { "user_id": &user_id, "revoked": true })
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))? as i64;

    // For expired, check if license type is time_limited and expires_at < now
    let now = Utc::now();
    let expired = collection
        .count_documents(doc! {
            "user_id": &user_id,
            "license_type.type": "time_limited",
            "license_type.expires_at": { "$lt": now.to_rfc3339() },
            "revoked": false
        })
        .await
        .unwrap_or(0) as i64;

    Ok((active - expired, revoked, expired, total))
}

async fn get_hourly_activity(
    collection: &mongodb::Collection<VerificationAttempt>,
    filter: mongodb::bson::Document,
) -> Result<Vec<HourlyActivity>, Error> {
    // Get last 24 hours of data
    let now = Utc::now();
    let yesterday = now - Duration::hours(24);
    
    let mut match_filter = filter;
    match_filter.insert("timestamp", doc! { "$gte": yesterday.to_rfc3339() });

    let pipeline = vec![
        doc! {
            "$match": match_filter
        },
        doc! {
            "$group": {
                "_id": {
                    "$dateToString": {
                        "format": "%H",
                        "date": { "$toDate": "$timestamp" }
                    }
                },
                "count": { "$sum": 1 }
            }
        },
        doc! {
            "$sort": { "_id": 1 }
        }
    ];

    let mut cursor = collection
        .aggregate(pipeline)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;

    let mut results = Vec::new();
    use futures::stream::StreamExt;
    
    while let Some(result) = cursor.next().await {
        match result {
            Ok(doc) => {
                let hour = doc.get_str("_id").unwrap_or("00").to_string();
                let count = doc.get_i64("count").unwrap_or(0);
                results.push(HourlyActivity {
                    hour: format!("{}:00", hour),
                    count,
                });
            }
            Err(e) => log::error!("Error reading hourly stat: {}", e),
        }
    }

    // Fill in missing hours with 0
    let mut hour_map: HashMap<String, i64> = HashMap::new();
    for item in results {
        hour_map.insert(item.hour.clone(), item.count);
    }

    let mut complete_results = Vec::new();
    for h in (0..24).step_by(4) {
        let hour_str = format!("{:02}:00", h);
        let count = *hour_map.get(&hour_str).unwrap_or(&0);
        complete_results.push(HourlyActivity {
            hour: hour_str,
            count,
        });
    }

    Ok(complete_results)
}

async fn get_daily_time_series(
    collection: &mongodb::Collection<VerificationAttempt>,
    filter: mongodb::bson::Document,
) -> Result<(Vec<TimeSeriesPoint>, Vec<TimeSeriesPoint>), Error> {
    let now = Utc::now();
    let thirty_days_ago = now - Duration::days(30);

    // Get daily data for last 30 days
    let mut daily_filter = filter.clone();
    daily_filter.insert("timestamp", doc! { "$gte": thirty_days_ago.to_rfc3339() });
    
    let pipeline = vec![
        doc! {
            "$match": daily_filter
        },
        doc! {
            "$group": {
                "_id": {
                    "$dateToString": {
                        "format": "%Y-%m-%d",
                        "date": { "$toDate": "$timestamp" }
                    }
                },
                "total": { "$sum": 1 },
                "successes": {
                    "$sum": {
                        "$cond": [{ "$eq": ["$success", true] }, 1, 0]
                    }
                }
            }
        },
        doc! {
            "$sort": { "_id": 1 }
        }
    ];

    let mut cursor = collection
        .aggregate(pipeline)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;

    let mut daily_results = Vec::new();
    use futures::stream::StreamExt;

    while let Some(result) = cursor.next().await {
        match result {
            Ok(doc) => {
                let date = doc.get_str("_id").unwrap_or("").to_string();
                let total = doc.get_i64("total").unwrap_or(0);
                let successes = doc.get_i64("successes").unwrap_or(0);
                let failures = total - successes;
                
                daily_results.push(TimeSeriesPoint {
                    date,
                    verifications: total,
                    successes,
                    failures,
                });
            }
            Err(e) => log::error!("Error reading daily stat: {}", e),
        }
    }

    // Generate monthly data (last 6 months)
    let six_months_ago = now - Duration::days(180);
    
    let mut monthly_filter = filter.clone();
    monthly_filter.insert("timestamp", doc! { "$gte": six_months_ago.to_rfc3339() });
    
    let monthly_pipeline = vec![
        doc! {
            "$match": monthly_filter
        },
        doc! {
            "$group": {
                "_id": {
                    "$dateToString": {
                        "format": "%Y-%m",
                        "date": { "$toDate": "$timestamp" }
                    }
                },
                "total": { "$sum": 1 },
                "successes": {
                    "$sum": {
                        "$cond": [{ "$eq": ["$success", true] }, 1, 0]
                    }
                }
            }
        },
        doc! {
            "$sort": { "_id": 1 }
        }
    ];

    let mut monthly_cursor = collection
        .aggregate(monthly_pipeline)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;

    let mut monthly_results = Vec::new();

    while let Some(result) = monthly_cursor.next().await {
        match result {
            Ok(doc) => {
                let date = doc.get_str("_id").unwrap_or("").to_string();
                let total = doc.get_i64("total").unwrap_or(0);
                let successes = doc.get_i64("successes").unwrap_or(0);
                let failures = total - successes;
                
                // Convert YYYY-MM to month name
                let month_name = if let Some(parts) = date.split('-').nth(1) {
                    match parts {
                        "01" => "Jan", "02" => "Feb", "03" => "Mar",
                        "04" => "Apr", "05" => "May", "06" => "Jun",
                        "07" => "Jul", "08" => "Aug", "09" => "Sep",
                        "10" => "Oct", "11" => "Nov", "12" => "Dec",
                        _ => "Unknown"
                    }
                } else {
                    "Unknown"
                };
                
                monthly_results.push(TimeSeriesPoint {
                    date: month_name.to_string(),
                    verifications: total,
                    successes,
                    failures,
                });
            }
            Err(e) => log::error!("Error reading monthly stat: {}", e),
        }
    }

    Ok((daily_results, monthly_results))
}

async fn get_top_binaries(
    attempt_collection: &mongodb::Collection<VerificationAttempt>,
    binary_collection: &mongodb::Collection<Binary>,
    filter: mongodb::bson::Document,
) -> Result<Vec<TopBinary>, Error> {
    let pipeline = vec![
        doc! { "$match": filter },
        doc! {
            "$group": {
                "_id": "$binary_id",
                "count": { "$sum": 1 },
                "unique_machines": {
                    "$addToSet": "$machine_fingerprint"
                }
            }
        },
        doc! {
            "$project": {
                "binary_id": "$_id",
                "count": 1,
                "unique_machines": { "$size": "$unique_machines" }
            }
        },
        doc! {
            "$sort": { "count": -1 }
        },
        doc! {
            "$limit": 10
        }
    ];

    let mut cursor = attempt_collection
        .aggregate(pipeline)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;

    let mut results = Vec::new();
    use futures::stream::StreamExt;

    while let Some(result) = cursor.next().await {
        match result {
            Ok(doc) => {
                let binary_id = doc.get_str("binary_id").unwrap_or("unknown").to_string();
                let count = doc.get_i64("count").unwrap_or(0);
                let unique_machines = doc.get_i32("unique_machines").unwrap_or(0) as i64;
                
                // Try to get binary name
                let name = if let Ok(Some(binary)) = binary_collection
                    .find_one(doc! { "binary_id": &binary_id })
                    .await
                {
                    binary.original_name
                } else {
                    binary_id.clone()
                };
                
                results.push(TopBinary {
                    binary_id,
                    name,
                    executions: count,
                    unique_machines,
                });
            }
            Err(e) => log::error!("Error reading top binary stat: {}", e),
        }
    }

    Ok(results)
}

async fn get_geographic_distribution(
    collection: &mongodb::Collection<VerificationAttempt>,
    filter: mongodb::bson::Document,
) -> Result<Vec<GeographicData>, Error> {
    // Load GeoIP database from environment variable
    let geoip_path = std::env::var("GEOIP_DB_PATH")
        .unwrap_or_else(|_| "/server/geoip/data/GeoLite2-Country.mmdb".to_string());
    
    let geoip_reader = match maxminddb::Reader::open_readfile(&geoip_path) {
        Ok(reader) => Some(reader),
        Err(e) => {
            log::warn!("Failed to load GeoIP database from {}: {}. Using fallback.", geoip_path, e);
            None
        }
    };

    let pipeline = vec![
        doc! { "$match": filter },
        doc! {
            "$group": {
                "_id": "$ip_address",
                "count": { "$sum": 1 }
            }
        },
        doc! {
            "$sort": { "count": -1 }
        },
        doc! {
            "$limit": 100
        }
    ];

    let mut cursor = collection
        .aggregate(pipeline)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;

    let mut country_map: HashMap<String, i64> = HashMap::new();
    let mut total_count = 0i64;
    use futures::stream::StreamExt;

    while let Some(result) = cursor.next().await {
        match result {
            Ok(doc) => {
                let ip = doc.get_str("_id").unwrap_or("Unknown").to_string();
                let count = doc.get_i64("count").unwrap_or(0);
                total_count += count;
                
                // Try to get country from GeoIP database
                let country = if let Some(ref reader) = geoip_reader {
                    // Parse IP address
                    match ip.parse::<std::net::IpAddr>() {
                        Ok(ip_addr) => {
                            match reader.lookup(ip_addr) {
                                Ok(lookup_result) => {
                                    match lookup_result.decode::<maxminddb::geoip2::Country>() {
                                        Ok(Some(country_data)) => {
                                            country_data.country.names.english
                                                .map(|s| s.to_string())
                                                .unwrap_or_else(|| "Unknown".to_string())
                                        }
                                        _ => "Unknown".to_string()
                                    }
                                }
                                Err(_) => "Unknown".to_string()
                            }
                        }
                        Err(_) => {
                            // Fallback for invalid IPs
                            if ip == "127.0.0.1" || ip.starts_with("127.") {
                                "Localhost".to_string()
                            } else if ip.starts_with("10.") || ip.starts_with("172.") || ip.starts_with("192.168.") {
                                "Private Network".to_string()
                            } else {
                                "Unknown".to_string()
                            }
                        }
                    }
                } else {
                    // Fallback if GeoIP database not available
                    if ip == "127.0.0.1" || ip.starts_with("127.") {
                        "Localhost".to_string()
                    } else if ip.starts_with("10.") || ip.starts_with("172.") || ip.starts_with("192.168.") {
                        "Private Network".to_string()
                    } else {
                        "Unknown".to_string()
                    }
                };
                
                *country_map.entry(country).or_insert(0) += count;
            }
            Err(e) => log::error!("Error reading geo stat: {}", e),
        }
    }

    let mut geo_results: Vec<GeographicData> = country_map
        .into_iter()
        .map(|(country, count)| {
            let percentage = if total_count > 0 {
                (count as f64 / total_count as f64 * 100.0).round() / 10.0 * 10.0
            } else {
                0.0
            };
            GeographicData {
                country,
                count,
                percentage,
            }
        })
        .collect();

    geo_results.sort_by(|a, b| b.count.cmp(&a.count));
    geo_results.truncate(5);

    Ok(geo_results)
}

async fn get_recent_activity(
    collection: &mongodb::Collection<VerificationAttempt>,
    filter: mongodb::bson::Document,
) -> Result<(i64, i64, i64), Error> {
    let now = Utc::now();
    let day_ago = now - Duration::hours(24);
    let week_ago = now - Duration::days(7);
    let month_ago = now - Duration::days(30);

    let mut last_24h_filter = filter.clone();
    last_24h_filter.insert("timestamp", doc! { "$gte": day_ago.to_rfc3339() });
    
    let last_24h = collection
        .count_documents(last_24h_filter)
        .await
        .unwrap_or(0) as i64;

    let mut last_7d_filter = filter.clone();
    last_7d_filter.insert("timestamp", doc! { "$gte": week_ago.to_rfc3339() });
    
    let last_7d = collection
        .count_documents(last_7d_filter)
        .await
        .unwrap_or(0) as i64;

    let mut last_30d_filter = filter.clone();
    last_30d_filter.insert("timestamp", doc! { "$gte": month_ago.to_rfc3339() });
    
    let last_30d = collection
        .count_documents(last_30d_filter)
        .await
        .unwrap_or(0) as i64;

    Ok((last_24h, last_7d, last_30d))
}
