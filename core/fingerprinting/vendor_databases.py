"""
Vendor Database Manager

Manages loading and updating of vendor signature databases.
"""

import json
from pathlib import Path
from typing import Dict
from loguru import logger


class VendorDatabaseManager:
    """
    Manages vendor signature databases for all fingerprinting methods.
    """

    def __init__(self, models_dir: str):
        """
        Initialize vendor database manager.

        Args:
            models_dir: Directory containing database JSON files
        """
        self.models_dir = Path(models_dir)
        self.databases = {}

    def load_database(self, db_name: str) -> Dict:
        """
        Load vendor database from JSON file.

        Args:
            db_name: Database filename (e.g., "ja3_vendor_db.json")

        Returns:
            Database dict or empty dict if not found
        """
        try:
            db_file = self.models_dir / db_name

            if db_file.exists():
                with open(db_file, 'r') as f:
                    db = json.load(f)
                logger.info(f"Loaded database: {db_name} ({len(db)} entries)")
                self.databases[db_name] = db
                return db
            else:
                logger.warning(f"Database not found: {db_file}")
                return {}

        except Exception as e:
            logger.error(f"Failed to load database {db_name}: {e}")
            return {}

    def save_database(self, db_name: str, data: Dict):
        """
        Save vendor database to JSON file.

        Args:
            db_name: Database filename
            data: Database dict
        """
        try:
            db_file = self.models_dir / db_name

            # Create directory if it doesn't exist
            db_file.parent.mkdir(parents=True, exist_ok=True)

            with open(db_file, 'w') as f:
                json.dump(data, f, indent=2)

            logger.info(f"Saved database: {db_name} ({len(data)} entries)")

        except Exception as e:
            logger.error(f"Failed to save database {db_name}: {e}")

    def update_signature(self, db_name: str, signature: str, info: Dict):
        """
        Update or add a signature to database.

        Args:
            db_name: Database filename
            signature: Signature key
            info: Signature information
        """
        if db_name not in self.databases:
            self.databases[db_name] = self.load_database(db_name)

        self.databases[db_name][signature] = info
        self.save_database(db_name, self.databases[db_name])

        logger.info(f"Updated signature in {db_name}: {signature}")
