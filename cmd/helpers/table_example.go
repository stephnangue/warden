package helpers

// Example usage of the table helper functions:
//
// 1. Using PrintTable with custom headers and data:
//
//    headers := []string{"Name", "Age", "City"}
//    data := [][]any{
//        {"Alice", 30, "New York"},
//        {"Bob", 25, "London"},
//        {"Charlie", 35, "Paris"},
//    }
//    helpers.PrintTable(headers, data)
//
// 2. Using PrintMapAsTable for map data:
//
//    mapData := map[string]any{
//        "token": "s.xxxxxxxxx",
//        "token_accessor": "xxxxxxxxx",
//        "token_duration": "768h",
//        "token_renewable": true,
//    }
//    helpers.PrintMapAsTable(mapData)
//
// 3. Using PrintTable with different column counts:
//
//    headers := []string{"ID", "Status", "Created", "Description"}
//    data := [][]any{
//        {1, "active", "2025-01-01", "First item"},
//        {2, "pending", "2025-01-02", "Second item"},
//    }
//    helpers.PrintTable(headers, data)
