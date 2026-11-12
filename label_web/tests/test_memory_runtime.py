import unittest

from memory_runtime import MIB, memory_setting, select_memory_policy


class MemoryPolicyTests(unittest.TestCase):
    def test_known_capacities_preserve_small_service_and_use_larger_plan(self):
        for capacity, worker, reserve, detector in ((512,360,96,1280), (1024,640,128,1280),
                                                    (1536,960,192,1600), (2048,1280,256,1600),
                                                    (4096,1280,512,1600)):
            with self.subTest(capacity=capacity):
                policy=select_memory_policy(capacity*MIB)
                self.assertEqual((policy["worker_limit_mb"],policy["reserve_mb"],policy["det_limit"]),
                                 (worker,reserve,detector))
                self.assertEqual(policy["service_stop_mb"],capacity-reserve)

    def test_unknown_capacity_never_authorizes_larger_budget(self):
        policy=select_memory_policy()
        self.assertIsNone(policy["service_limit_mb"])
        self.assertIsNone(policy["service_stop_mb"])
        self.assertEqual(policy["worker_limit_mb"],360)
        self.assertEqual(policy["policy"],"conservative_fallback")
        with self.assertRaises(ValueError):
            select_memory_policy(worker_mb=768)

    def test_configuration_only_tightens_capacity_budget(self):
        policy=select_memory_policy(2048*MIB,worker_mb=768,reserve_mb=320)
        self.assertEqual((policy["worker_limit_mb"],policy["reserve_mb"]),(768,320))
        self.assertTrue(policy["configured"])
        small=select_memory_policy(512*MIB,reserve_mb=128)
        self.assertEqual(small["worker_limit_mb"],328)
        for capacity,worker,reserve in ((512,768,None),(2048,1281,None),(2048,None,96),(512,360,128),
                                         (512,None,512),(256,None,None)):
            with self.subTest(capacity=capacity,worker=worker,reserve=reserve), self.assertRaises(ValueError):
                select_memory_policy(capacity*MIB,worker,reserve)

    def test_invalid_settings_never_leak_supplied_value(self):
        for value in (True,False,[],{},12.5,"secret-value", "nan", "384.0",127,1281):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError) as caught:
                memory_setting(value,"worker",128,1280)
            self.assertNotIn("secret-value",str(caught.exception))
        self.assertIsNone(memory_setting("","worker",128,1280))
        self.assertEqual(memory_setting("768","worker",128,1280),768)


if __name__=="__main__":
    unittest.main()
