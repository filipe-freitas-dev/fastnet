//! Interest management for scalable multiplayer games.
//!
//! This module provides spatial filtering to reduce bandwidth by only
//! sending updates about entities within a player's area of interest.
//!
//! # Use Cases
//!
//! - MMO games with hundreds of players
//! - Battle royale with shrinking play area
//! - Open world games with distant entities
//!
//! # Algorithm
//!
//! Uses a spatial hash grid for O(1) entity lookups:
//! - World divided into fixed-size cells
//! - Each entity belongs to one cell
//! - Query returns entities in nearby cells
//!
//! # Example
//!
//! ```rust,ignore
//! use fastnet::net::fast::interest::{InterestGrid, Entity};
//!
//! let mut grid = InterestGrid::new(100.0); // 100 unit cells
//!
//! // Register entities
//! grid.insert(1, 150.0, 200.0);
//! grid.insert(2, 155.0, 205.0);
//! grid.insert(3, 500.0, 500.0);
//!
//! // Query nearby entities (within 2 cells)
//! let nearby = grid.query(150.0, 200.0, 2);
//! assert!(nearby.contains(&1));
//! assert!(nearby.contains(&2));
//! assert!(!nearby.contains(&3)); // Too far
//! ```

use std::collections::{HashMap, HashSet};

/// Entity ID type.
pub type EntityId = u32;

/// 2D position.
#[derive(Debug, Clone, Copy, Default)]
pub struct Position {
    pub x: f32,
    pub y: f32,
}

impl Position {
    #[inline]
    pub fn new(x: f32, y: f32) -> Self {
        Self { x, y }
    }

    #[inline]
    pub fn distance_squared(&self, other: &Position) -> f32 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        dx * dx + dy * dy
    }
}

/// Cell coordinate in the spatial grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CellCoord {
    x: i32,
    y: i32,
}

/// Spatial hash grid for efficient proximity queries.
pub struct InterestGrid {
    /// Cell size in world units.
    cell_size: f32,
    /// Inverse cell size (for faster division).
    inv_cell_size: f32,
    /// Cells containing entity sets.
    cells: HashMap<CellCoord, HashSet<EntityId>>,
    /// Entity positions.
    positions: HashMap<EntityId, Position>,
    /// Entity to cell mapping.
    entity_cells: HashMap<EntityId, CellCoord>,
}

impl InterestGrid {
    /// Create a new grid with the specified cell size.
    ///
    /// Cell size should be roughly the radius of interest.
    pub fn new(cell_size: f32) -> Self {
        let cell_size = cell_size.max(1.0);
        Self {
            cell_size,
            inv_cell_size: 1.0 / cell_size,
            cells: HashMap::with_capacity(256),
            positions: HashMap::with_capacity(1024),
            entity_cells: HashMap::with_capacity(1024),
        }
    }

    /// Insert or update an entity's position.
    #[inline]
    pub fn insert(&mut self, id: EntityId, x: f32, y: f32) {
        let new_cell = self.pos_to_cell(x, y);
        let pos = Position::new(x, y);

        // Remove from old cell if moved
        if let Some(&old_cell) = self.entity_cells.get(&id) {
            if old_cell != new_cell {
                if let Some(cell) = self.cells.get_mut(&old_cell) {
                    cell.remove(&id);
                }
            }
        }

        // Add to new cell
        self.cells
            .entry(new_cell)
            .or_insert_with(|| HashSet::with_capacity(16))
            .insert(id);
        
        self.positions.insert(id, pos);
        self.entity_cells.insert(id, new_cell);
    }

    /// Remove an entity from the grid.
    pub fn remove(&mut self, id: EntityId) {
        if let Some(cell_coord) = self.entity_cells.remove(&id) {
            if let Some(cell) = self.cells.get_mut(&cell_coord) {
                cell.remove(&id);
            }
        }
        self.positions.remove(&id);
    }

    /// Query entities near a position.
    ///
    /// Returns all entities within `radius` cells of the position.
    pub fn query(&self, x: f32, y: f32, radius: i32) -> Vec<EntityId> {
        let center = self.pos_to_cell(x, y);
        let mut result = Vec::with_capacity(64);

        for dx in -radius..=radius {
            for dy in -radius..=radius {
                let cell = CellCoord {
                    x: center.x + dx,
                    y: center.y + dy,
                };
                if let Some(entities) = self.cells.get(&cell) {
                    result.extend(entities.iter().copied());
                }
            }
        }

        result
    }

    /// Query entities within a distance (exact distance check).
    pub fn query_radius(&self, x: f32, y: f32, radius: f32) -> Vec<EntityId> {
        let cell_radius = (radius * self.inv_cell_size).ceil() as i32;
        let center = Position::new(x, y);
        let radius_sq = radius * radius;

        self.query(x, y, cell_radius)
            .into_iter()
            .filter(|id| {
                self.positions.get(id)
                    .map(|pos| pos.distance_squared(&center) <= radius_sq)
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Get entities that entered interest area since last check.
    pub fn diff_entered(
        &self,
        x: f32,
        y: f32,
        radius: i32,
        previous: &HashSet<EntityId>,
    ) -> Vec<EntityId> {
        self.query(x, y, radius)
            .into_iter()
            .filter(|id| !previous.contains(id))
            .collect()
    }

    /// Get entities that left interest area since last check.
    pub fn diff_left(
        &self,
        x: f32,
        y: f32,
        radius: i32,
        previous: &HashSet<EntityId>,
    ) -> Vec<EntityId> {
        let current: HashSet<_> = self.query(x, y, radius).into_iter().collect();
        previous.iter()
            .filter(|id| !current.contains(id))
            .copied()
            .collect()
    }

    /// Get entity position.
    #[inline]
    pub fn get_position(&self, id: EntityId) -> Option<Position> {
        self.positions.get(&id).copied()
    }

    /// Total number of entities.
    #[inline]
    pub fn len(&self) -> usize {
        self.positions.len()
    }

    /// Check if empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.positions.is_empty()
    }

    /// Clear all entities.
    pub fn clear(&mut self) {
        self.cells.clear();
        self.positions.clear();
        self.entity_cells.clear();
    }

    /// Convert world position to cell coordinate.
    #[inline]
    fn pos_to_cell(&self, x: f32, y: f32) -> CellCoord {
        CellCoord {
            x: (x * self.inv_cell_size).floor() as i32,
            y: (y * self.inv_cell_size).floor() as i32,
        }
    }
}

/// Per-player interest state for tracking changes.
pub struct PlayerInterest {
    /// Player's entity ID.
    pub player_id: EntityId,
    /// Currently visible entities.
    visible: HashSet<EntityId>,
    /// Interest radius in cells.
    radius: i32,
}

impl PlayerInterest {
    pub fn new(player_id: EntityId, radius: i32) -> Self {
        Self {
            player_id,
            visible: HashSet::with_capacity(256),
            radius,
        }
    }

    /// Update visibility and return changes.
    ///
    /// Returns (entered, left) entity lists.
    pub fn update(&mut self, grid: &InterestGrid) -> (Vec<EntityId>, Vec<EntityId>) {
        let pos = match grid.get_position(self.player_id) {
            Some(p) => p,
            None => return (vec![], vec![]),
        };

        let entered = grid.diff_entered(pos.x, pos.y, self.radius, &self.visible);
        let left = grid.diff_left(pos.x, pos.y, self.radius, &self.visible);

        // Update visible set
        for id in &entered {
            self.visible.insert(*id);
        }
        for id in &left {
            self.visible.remove(id);
        }

        (entered, left)
    }

    /// Get currently visible entities.
    #[inline]
    pub fn visible(&self) -> &HashSet<EntityId> {
        &self.visible
    }

    /// Clear visibility.
    pub fn clear(&mut self) {
        self.visible.clear();
    }
}

/// Priority levels for entity updates.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UpdatePriority {
    /// Critical - always send (player characters).
    Critical = 0,
    /// High - important entities nearby.
    High = 1,
    /// Normal - regular entities.
    Normal = 2,
    /// Low - distant or less important.
    Low = 3,
}

/// Priority calculator for entity updates.
pub struct PriorityCalculator {
    /// Distance threshold for high priority.
    high_distance: f32,
    /// Distance threshold for normal priority.
    normal_distance: f32,
}

impl PriorityCalculator {
    pub fn new(high_distance: f32, normal_distance: f32) -> Self {
        Self {
            high_distance,
            normal_distance,
        }
    }

    /// Calculate update priority based on distance.
    pub fn calculate(&self, distance: f32, is_player: bool) -> UpdatePriority {
        if is_player {
            return UpdatePriority::Critical;
        }
        if distance <= self.high_distance {
            UpdatePriority::High
        } else if distance <= self.normal_distance {
            UpdatePriority::Normal
        } else {
            UpdatePriority::Low
        }
    }
}

impl Default for PriorityCalculator {
    fn default() -> Self {
        Self::new(50.0, 150.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grid_insert_query() {
        let mut grid = InterestGrid::new(10.0);

        grid.insert(1, 5.0, 5.0);
        grid.insert(2, 15.0, 15.0);
        grid.insert(3, 100.0, 100.0);

        let nearby = grid.query(5.0, 5.0, 1);
        assert!(nearby.contains(&1));
        assert!(nearby.contains(&2)); // Within 1 cell
        assert!(!nearby.contains(&3)); // Too far
    }

    #[test]
    fn test_grid_move_entity() {
        let mut grid = InterestGrid::new(10.0);

        grid.insert(1, 5.0, 5.0);
        assert!(grid.query(5.0, 5.0, 0).contains(&1));

        // Move far away
        grid.insert(1, 100.0, 100.0);
        assert!(!grid.query(5.0, 5.0, 0).contains(&1));
        assert!(grid.query(100.0, 100.0, 0).contains(&1));
    }

    #[test]
    fn test_grid_remove() {
        let mut grid = InterestGrid::new(10.0);

        grid.insert(1, 5.0, 5.0);
        assert!(grid.query(5.0, 5.0, 0).contains(&1));

        grid.remove(1);
        assert!(!grid.query(5.0, 5.0, 0).contains(&1));
    }

    #[test]
    fn test_query_radius() {
        let mut grid = InterestGrid::new(10.0);

        grid.insert(1, 0.0, 0.0);
        grid.insert(2, 5.0, 0.0);
        grid.insert(3, 15.0, 0.0);

        let nearby = grid.query_radius(0.0, 0.0, 10.0);
        assert!(nearby.contains(&1));
        assert!(nearby.contains(&2)); // Distance 5
        assert!(!nearby.contains(&3)); // Distance 15 > 10
    }

    #[test]
    fn test_player_interest() {
        let mut grid = InterestGrid::new(10.0);
        grid.insert(100, 0.0, 0.0); // Player
        grid.insert(1, 5.0, 5.0);   // Nearby entity

        let mut interest = PlayerInterest::new(100, 1);
        
        let (entered, left) = interest.update(&grid);
        assert!(entered.contains(&1));
        assert!(left.is_empty());

        // Entity moves away
        grid.insert(1, 500.0, 500.0);
        let (entered, left) = interest.update(&grid);
        assert!(entered.is_empty());
        assert!(left.contains(&1));
    }

    #[test]
    fn test_priority_calculator() {
        let calc = PriorityCalculator::new(50.0, 150.0);

        assert_eq!(calc.calculate(0.0, true), UpdatePriority::Critical);
        assert_eq!(calc.calculate(30.0, false), UpdatePriority::High);
        assert_eq!(calc.calculate(100.0, false), UpdatePriority::Normal);
        assert_eq!(calc.calculate(200.0, false), UpdatePriority::Low);
    }
}
