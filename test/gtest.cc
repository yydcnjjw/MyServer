#include <gtest/gtest.h>
#include <iostream>

#include "utils/error_util.h"
#include "utils/file_util.h"

using namespace std;
int main(int argc, char *argv[]) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

TEST(ErrorTest, error) {
    Utils::VoidResult result =
        Utils::VoidResult::ErrorResult<Utils::SysError>("syserror", 10);
    cout << result.str() << endl;
    Utils::Result<ssize_t> r(
        1, Utils::VoidResult::ErrorResult<Utils::NotSupport>());
    r.Get() += 1;
    cout << r.Get() << endl;
    EXPECT_TRUE(r.Get() == 2);
}

bool MemFileTest() {
    Utils::VoidResult result;
    Utils::File *file = new Utils::MemFile("test");
    if (!file->IsExist()) {
        result = file->Create();
        if (!result.IsOK()) {
            cout << result.str() << endl;
            return false;
        }
    }

    Utils::FileWriter fw(file->GetFileDesc());
    result = fw.Append("abcdefg");

    if (!result.IsOK()) {
        cout << result.str() << endl;
        return false;
    }
    result = fw.Flush();

    if (!result.IsOK()) {
        cout << result.str() << endl;
        return false;
    }

    file->Seek(0, SEEK_SET);

    Utils::FileReader fr(file->GetFileDesc());
    std::string line;
    result = fr.ReadLine(line);
    if (!result.IsOK()) {
        cout << result.str() << endl;
        return false;
    }

    cout << "read line:" << endl;
    cout << line << endl;
    return true;
}

TEST(FileApiTest, MemFileTest) { EXPECT_TRUE(MemFileTest()); }

bool FileCacheTest() {
    Utils::FileCache *filecache = Utils::GetFileCache();
    auto result = filecache->FileGet("test.file");
    if (!result.IsOK()) {
	cout << result.str() << endl;
	return false;
    }

    Utils::FileCacheEntity& entity = result.Get();
    std::string s;
    
    cout << entity.fd << endl;
    cout << entity.size << endl;
    s.append(entity.data, entity.size);
    cout << s << endl;

    result = filecache->FileGet("test.file");
    if (!result.IsOK()) {
	cout << result.str() << endl;
	return false;
    }

    entity = result.Get();
    cout << entity.fd << endl;
    cout << entity.size << endl;
    s.append(entity.data, entity.size);
    cout << s << endl;
    
    return true;
}

TEST(FileApiTest, FileCacheTest) { EXPECT_TRUE(FileCacheTest()); }
