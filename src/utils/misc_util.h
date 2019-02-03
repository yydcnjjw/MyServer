#ifndef MISC_UTIL_H
#define MISC_UTIL_H
namespace Utils {
template <typename Class, typename T> inline bool instanceof (const T *ptr) {
    return dynamic_cast<const Class *>(ptr) != nullptr;
}

} // namespace Utils

#endif /* MISC_UTIL_H */
