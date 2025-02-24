import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

class WeddingBudgetDataset:
    def __init__(self):
        # Sample data structure
        self.data = {
            'total_budget': [],
            'guest_count': [],
            'is_destination': [],
            'season': [],  # 0: Off-peak, 1: Peak
            'location_tier': [],  # 0: Tier 2/3, 1: Tier 1 city
            'wedding_type': [],  # Encoded wedding types
            'venue_allocation': [],
            'catering_allocation': [],
            'decoration_allocation': [],
            'photography_allocation': [],
            'attire_allocation': [],
            'entertainment_allocation': [],
            'mehendi_allocation': [],
            'makeup_allocation': []
        }
        
    def generate_synthetic_data(self, num_samples=1000):
        """Generate synthetic wedding budget data based on typical Indian wedding patterns"""
        np.random.seed(42)
        
        # Generate total budgets (ranging from 5L to 50L)
        total_budgets = np.random.uniform(500000, 5000000, num_samples)
        
        # Generate guest counts (50 to 1000)
        guest_counts = np.random.randint(50, 1000, num_samples)
        
        # Generate binary features
        is_destination = np.random.choice([0, 1], num_samples, p=[0.8, 0.2])
        season = np.random.choice([0, 1], num_samples, p=[0.6, 0.4])
        location_tier = np.random.choice([0, 1], num_samples, p=[0.7, 0.3])
        
        # Wedding type encoding
        wedding_types = np.random.choice(range(7), num_samples, p=[0.3, 0.3, 0.1, 0.1, 0.1, 0.05, 0.05])
        
        # Generate allocation percentages based on wedding type and other features
        for i in range(num_samples):
            allocations = self._generate_allocations(
                total_budgets[i],
                guest_counts[i],
                is_destination[i],
                season[i],
                location_tier[i],
                wedding_types[i]
            )
            
            # Store the data
            self.data['total_budget'].append(total_budgets[i])
            self.data['guest_count'].append(guest_counts[i])
            self.data['is_destination'].append(is_destination[i])
            self.data['season'].append(season[i])
            self.data['location_tier'].append(location_tier[i])
            self.data['wedding_type'].append(wedding_types[i])
            
            for category, allocation in zip(
                ['venue', 'catering', 'decoration', 'photography', 
                 'attire', 'entertainment', 'mehendi', 'makeup'],
                allocations
            ):
                self.data[f'{category}_allocation'].append(allocation)
    
    def _generate_allocations(self, budget, guests, is_destination, season, location, wedding_type):
        """Generate realistic budget allocations based on wedding characteristics"""
        base_allocations = {
            'venue': 0.25,
            'catering': 0.30,
            'decoration': 0.15,
            'photography': 0.10,
            'attire': 0.10,
            'entertainment': 0.05,
            'mehendi': 0.025,
            'makeup': 0.025
        }
        
        # Adjust allocations based on features
        if is_destination:
            base_allocations['venue'] += 0.10
            base_allocations['catering'] -= 0.05
            base_allocations['decoration'] -= 0.05
            
        if season == 1:  # Peak season
            base_allocations['venue'] += 0.05
            base_allocations['catering'] -= 0.05
            
        if location == 1:  # Tier 1 city
            base_allocations['venue'] += 0.05
            base_allocations['catering'] += 0.05
            base_allocations['decoration'] -= 0.10
            
        # Add some random variation (±5%)
        allocations = [
            max(0.05, min(0.5, alloc + np.random.uniform(-0.05, 0.05)))
            for alloc in base_allocations.values()
        ]
        
        # Normalize to ensure sum is 1
        return [a / sum(allocations) for a in allocations]
    
    def get_training_data(self):
        """Prepare data for model training"""
        df = pd.DataFrame(self.data)
        
        # Split features and targets
        X = df[['total_budget', 'guest_count', 'is_destination', 'season', 
                'location_tier', 'wedding_type']]
        y = df[[col for col in df.columns if 'allocation' in col]]
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Split into train and test sets
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42
        )
        
        return X_train, X_test, y_train, y_test, scaler 