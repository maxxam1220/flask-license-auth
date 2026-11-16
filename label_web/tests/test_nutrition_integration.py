"""Nutrition decisions must be recalculated from each pass's printed evidence."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from inspection_evidence import augment


class NutritionIntegrationTests(unittest.TestCase):
    def test_database_nutrition_evidence_is_not_erased_by_logic_refresh(self):
        comparison={'key':'nutrition_12','source':'database','status':'fail',
                    'expected':'脂肪 0.1公克 0.1公克','actual':'脂肪 0.1公克 0.9公克'}
        result={'checks':[deepcopy(comparison)]}
        with patch('inspection_evidence.nutrition_checks',return_value=[]):
            augment(result,{'lines':[]})
        self.assertIn(comparison,result['checks'])
        self.assertEqual(result['status'],'fail')

    def test_reaugmentation_replaces_old_nutrition_decisions(self):
        result={'checks':[{'key':'product','status':'pass'},
                          {'key':'nutrition_old','status':'fail'}]}
        ocr={'lines':[]}
        current={'key':'nutrition_new','status':'review','label':'營養換算','line_ids':[1]}
        with patch('inspection_evidence.nutrition_checks',return_value=[current]) as call:
            augment(result,ocr)
            call.assert_called_once_with(ocr)
            first=deepcopy(result)
            augment(result,ocr)
        self.assertEqual(result,first)
        self.assertEqual(result['counts']['fail'],0)
        self.assertEqual(result['status'],'review')

    def test_multiple_label_scope_demotes_nutrition_passes(self):
        result={'checks':[]}
        with patch('inspection_evidence.nutrition_checks',return_value=[
            {'key':'nutrition_fat','status':'pass','score':1.,'line_ids':[2]}]):
            augment(result,{'lines':[],'label_scope':{'status':'multiple'},'provider':'openai'})
        check=next(item for item in result['checks'] if item['key']=='nutrition_fat')
        self.assertEqual(check['status'],'review')
        self.assertIsNone(check['score'])
        self.assertEqual(check['score_kind'],'uncertainty_gate')


if __name__=='__main__': unittest.main()
