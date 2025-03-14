import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from io import BytesIO
import datetime
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.fonts import addMapping
# Import TensorFlow Lite instead of full TensorFlow
import tensorflow as tf
from tensorflow import lite

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
            'makeup_hair_allocation': []
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
                 'attire', 'entertainment', 'mehendi', 'makeup_hair'],
                allocations
            ):
                self.data[f'{category}_allocation'].append(allocation)
    
    def _generate_allocations(self, budget, guests, is_destination, season, location, wedding_type):
        """Generate realistic budget allocations based on wedding characteristics and priorities"""
        # Define base allocations with priorities (1: High, 2: Medium, 3: Low)
        base_allocations = {
            'venue': {'percentage': 0.25, 'priority': 1},
            'catering': {'percentage': 0.30, 'priority': 1},
            'decoration': {'percentage': 0.15, 'priority': 2},
            'photography': {'percentage': 0.10, 'priority': 2},
            'attire': {'percentage': 0.10, 'priority': 2},
            'entertainment': {'percentage': 0.05, 'priority': 3},
            'mehendi': {'percentage': 0.025, 'priority': 3},
            'makeup_hair': {'percentage': 0.025, 'priority': 3}
        }
        
        # Adjust allocations based on features and priorities
        if is_destination:
            base_allocations['venue']['percentage'] += 0.10
            base_allocations['catering']['percentage'] -= 0.05
            base_allocations['decoration']['percentage'] -= 0.05
            
        if season == 1:  # Peak season
            for category in base_allocations:
                if base_allocations[category]['priority'] == 1:
                    base_allocations[category]['percentage'] += 0.02
                elif base_allocations[category]['priority'] == 3:
                    base_allocations[category]['percentage'] -= 0.01
            
        # Extract just the percentages for final calculation
        allocations = [item['percentage'] for item in base_allocations.values()]
        
        # Add some random variation (±5%)
        allocations = [
            max(0.05, min(0.5, alloc + np.random.uniform(-0.05, 0.05)))
            for alloc in allocations
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

    def convert_model_to_tflite(self, model):
        """Convert the trained model to TensorFlow Lite format"""
        converter = lite.TFLiteConverter.from_keras_model(model)
        tflite_model = converter.convert()
        return tflite_model

class BudgetReportGenerator:
    def __init__(self, wedding_budget, allocations, total_spent, total_savings, recommendations, tips):
        self.wedding_budget = wedding_budget
        self.allocations = allocations
        self.total_spent = total_spent
        self.total_savings = total_savings
        self.recommendations = recommendations
        self.tips = tips
        self.buffer = BytesIO()
        
        # Register a Unicode-compatible font
        try:
            # Try to register DejaVuSans (which has good Unicode support)
            pdfmetrics.registerFont(TTFont('DejaVuSans', 'DejaVuSans.ttf'))
        except:
            pass  # If font registration fails, we'll fall back to a simpler solution
        
    def format_currency(self, amount):
        """Format currency with 'Rs.' instead of ₹ symbol"""
        return f"Rs. {amount:,.2f}"
        
    def generate_pdf(self):
        doc = SimpleDocTemplate(
            self.buffer,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        elements = []
        styles = getSampleStyleSheet()
        
        # Use DejaVuSans if registered, otherwise use default font
        try:
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                fontName='Helvetica-Bold'
            )
        except:
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30
            )
        
        # Add title
        elements.append(Paragraph("Wedding Budget Report", title_style))
        elements.append(Spacer(1, 12))
        
        # Create overview table with Rs. instead of ₹
        overview_data = [
            ["Total Budget", self.format_currency(self.wedding_budget.total_budget)],
            ["Total Spent", self.format_currency(self.total_spent)],
            ["Total Savings", self.format_currency(self.total_savings)],
            ["Wedding Date", self.wedding_budget.wedding_date.strftime("%B %d, %Y")],
            ["Guest Count", str(self.wedding_budget.guest_count)]
        ]
        
        # Rest of the table styling remains the same
        overview_table = Table(overview_data, colWidths=[200, 200])
        overview_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(overview_table)
        elements.append(Spacer(1, 20))
        
        # Add allocations section with Rs. instead of ₹
        elements.append(Paragraph("Budget Allocations", styles['Heading2']))
        elements.append(Spacer(1, 12))
        
        allocations_data = [["Category", "Allocated", "Spent", "Remaining"]]
        for alloc in self.allocations:
            remaining = alloc.allocated_amount - alloc.actual_spent
            allocations_data.append([
                alloc.category,
                self.format_currency(alloc.allocated_amount),
                self.format_currency(alloc.actual_spent),
                self.format_currency(remaining)
            ])
        
        # Rest of the code remains the same...
        alloc_table = Table(allocations_data, colWidths=[100, 100, 100, 100])
        alloc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(alloc_table)
        elements.append(Spacer(1, 20))
        
        # Add cost-saving tips
        if self.tips:
            elements.append(Paragraph("Cost-Saving Tips", styles['Heading2']))
            elements.append(Spacer(1, 12))
            for tip in self.tips:
                # Replace ₹ with Rs. in the potential savings text if present
                potential_savings = tip['potential_savings']
                if '₹' in potential_savings:
                    potential_savings = potential_savings.replace('₹', 'Rs. ')
                
                elements.append(Paragraph(
                    f"• {tip['category']}: {tip['tip']} (Potential Savings: {potential_savings})",
                    styles['Normal']
                ))
                elements.append(Spacer(1, 6))
        
        # Build PDF
        doc.build(elements)
        pdf = self.buffer.getvalue()
        self.buffer.close()
        return pdf 