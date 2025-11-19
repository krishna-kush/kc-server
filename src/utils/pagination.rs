/// Reusable utilities for MongoDB pagination and sorting
use mongodb::bson::{doc, Document};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct PaginationParams {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
}

impl PaginationParams {
    /// Get the page number (defaults to 1, minimum 1)
    pub fn page(&self) -> i64 {
        self.page.unwrap_or(1).max(1)
    }

    /// Get items per page (defaults to 10, min 1, max 100)
    pub fn per_page(&self) -> i64 {
        self.per_page.unwrap_or(10).min(100).max(1)
    }

    /// Calculate skip value for MongoDB
    pub fn skip(&self) -> u64 {
        ((self.page() - 1) * self.per_page()) as u64
    }

    /// Get limit for MongoDB
    pub fn limit(&self) -> i64 {
        self.per_page()
    }

    /// Get sort order (1 for asc, -1 for desc)
    pub fn sort_direction(&self) -> i32 {
        match self.sort_order.as_deref() {
            Some("asc") => 1,
            _ => -1, // Default to descending
        }
    }

    /// Build MongoDB sort document
    /// 
    /// # Arguments
    /// * `default_field` - Default field to sort by (e.g., "created_at")
    /// * `field_map` - Optional mapping of frontend field names to database field names
    pub fn build_sort_doc(
        &self,
        default_field: &str,
        field_map: Option<&[(&str, &str)]>,
    ) -> Document {
        let sort_field = self.sort_by.as_deref().unwrap_or(default_field);
        
        // Map frontend field name to database field name if mapping provided
        let db_field = if let Some(map) = field_map {
            map.iter()
                .find(|(frontend, _)| *frontend == sort_field)
                .map(|(_, backend)| *backend)
                .unwrap_or(default_field)
        } else {
            sort_field
        };

        doc! { db_field: self.sort_direction() }
    }

    /// Calculate total pages from total count
    pub fn calculate_total_pages(&self, total: u64) -> i64 {
        ((total as f64) / (self.per_page() as f64)).ceil() as i64
    }
}

/// Response wrapper for paginated results
#[derive(Debug, serde::Serialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: u64,
    pub page: i64,
    pub per_page: i64,
    pub total_pages: i64,
}

impl<T> PaginatedResponse<T> {
    pub fn new(data: Vec<T>, total: u64, params: &PaginationParams) -> Self {
        Self {
            data,
            total,
            page: params.page(),
            per_page: params.per_page(),
            total_pages: params.calculate_total_pages(total),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pagination_defaults() {
        let params = PaginationParams {
            page: None,
            per_page: None,
            sort_by: None,
            sort_order: None,
        };

        assert_eq!(params.page(), 1);
        assert_eq!(params.per_page(), 10);
        assert_eq!(params.skip(), 0);
    }

    #[test]
    fn test_pagination_calculations() {
        let params = PaginationParams {
            page: Some(3),
            per_page: Some(20),
            sort_by: None,
            sort_order: None,
        };

        assert_eq!(params.page(), 3);
        assert_eq!(params.per_page(), 20);
        assert_eq!(params.skip(), 40); // (3-1) * 20
        assert_eq!(params.calculate_total_pages(100), 5); // 100 / 20
    }

    #[test]
    fn test_sort_direction() {
        let asc_params = PaginationParams {
            page: None,
            per_page: None,
            sort_by: None,
            sort_order: Some("asc".to_string()),
        };
        assert_eq!(asc_params.sort_direction(), 1);

        let desc_params = PaginationParams {
            page: None,
            per_page: None,
            sort_by: None,
            sort_order: Some("desc".to_string()),
        };
        assert_eq!(desc_params.sort_direction(), -1);
    }

    #[test]
    fn test_build_sort_doc() {
        let params = PaginationParams {
            page: None,
            per_page: None,
            sort_by: Some("name".to_string()),
            sort_order: Some("asc".to_string()),
        };

        let field_map = [
            ("name", "original_name"),
            ("created", "created_at"),
        ];

        let sort_doc = params.build_sort_doc("created_at", Some(&field_map));
        assert_eq!(sort_doc.get_str("original_name").unwrap(), "1"); // Mapped field with asc order
    }
}
