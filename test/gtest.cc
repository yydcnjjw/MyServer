#include <gtest/gtest.h>
#include <iostream>

#include "utils/error_util.h"


int main(int argc, char *argv[]) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

TEST(ErrorTest, error) {
    Utils::Result<ssize_t> r(1, Utils::VoidResult::ErrorResult<Utils::NotSupport>());
    std::cout << r.Get() << std::endl;
    std::cout << r.IsOK() << std::endl;
    
    EXPECT_TRUE(r.Get() == 1);
}
