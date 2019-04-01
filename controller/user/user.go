package user

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dgrijalva/jwt-go"
	"github.com/garyburd/redigo/redis"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/shen100/golang123/config"
	"github.com/shen100/golang123/controller/common"
	"github.com/shen100/golang123/controller/mail"
	"github.com/shen100/golang123/model"
	"github.com/shen100/golang123/utils"
)

const (
	activeDuration = 24 * 60 * 60
	resetDuration  = 24 * 60 * 60
)

func sendMail(action string, title string, curTime int64, user model.User, c *gin.Context) {
	siteName := config.ServerConfig.SiteName
	siteURL := "https://" + config.ServerConfig.Host
	secretStr := fmt.Sprintf("%d%s%s", curTime, user.Email, user.Pass)
	secretStr = fmt.Sprintf("%x", md5.Sum([]byte(secretStr)))
	actionURL := siteURL + action + "/%d/%s"

	actionURL = fmt.Sprintf(actionURL, user.ID, secretStr)

	fmt.Println(actionURL)

	content := "<p><b>亲爱的" + user.Name + ":</b></p>" +
		"<p>我们收到您在 " + siteName + " 的注册信息, 请点击下面的链接, 或粘贴到浏览器地址栏来激活帐号.</p>" +
		"<a href=\"" + actionURL + "\">" + actionURL + "</a>" +
		"<p>如果您没有在 " + siteName + " 填写过注册信息, 说明有人滥用了您的邮箱, 请删除此邮件, 我们对给您造成的打扰感到抱歉.</p>" +
		"<p>" + siteName + " 谨上.</p>"

	if action == "/reset" {
		content = "<p><b>亲爱的" + user.Name + ":</b></p>" +
			"<p>你的密码重设要求已经得到验证。请点击以下链接, 或粘贴到浏览器地址栏来设置新的密码: </p>" +
			"<a href=\"" + actionURL + "\">" + actionURL + "</a>" +
			"<p>感谢你对" + siteName + "的支持，希望你在" + siteName + "的体验有益且愉快。</p>" +
			"<p>(这是一封自动产生的email，请勿回复。)</p>"
	}
	content += "<p><img src=\"" + siteURL + "/images/logo.png\" style=\"height: 42px;\"/></p>"
	//fmt.Println(content)

	mail.SendMail(user.Email, title, content)
}

func verifyLink(cacheKey string, c *gin.Context) (model.User, error) {
	var user model.User
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil || userID <= 0 {
		return user, errors.New("无效的链接")
	}
	secret := c.Param("secret")
	if secret == "" {
		return user, errors.New("无效的链接")
	}
	RedisConn := model.RedisPool.Get()
	defer RedisConn.Close()

	emailTime, redisErr := redis.Int64(RedisConn.Do("GET", cacheKey+fmt.Sprintf("%d", userID)))
	if redisErr != nil {
		return user, errors.New("无效的链接")
	}

	if err := model.DB.First(&user, userID).Error; err != nil {
		return user, errors.New("无效的链接")
	}

	secretStr := fmt.Sprintf("%d%s%s", emailTime, user.Email, user.Pass)
	secretStr = fmt.Sprintf("%x", md5.Sum([]byte(secretStr)))

	if secret != secretStr {
		fmt.Println(secret, secretStr)
		return user, errors.New("无效的链接")
	}
	return user, nil
}

// ActiveSendMail 发送激活账号的邮件
func ActiveSendMail(c *gin.Context) {
	SendErrJSON := common.SendErrJSON
	// 接收到的email参数是加密后的，不能加email验证规则
	type ReqData struct {
		Email string `json:"email" binding:"required"`
	}

	var reqData ReqData
	// 只接收一个email参数
	if err := c.ShouldBindWith(&reqData, binding.JSON); err != nil {
		SendErrJSON("参数无效", c)
		return
	}

	var user model.User
	user.Email = reqData.Email

	var decodeBytes []byte
	var decodedErr error
	if decodeBytes, decodedErr = base64.StdEncoding.DecodeString(user.Email); decodedErr != nil {
		SendErrJSON("参数无效", c)
		return
	}
	user.Email = string(decodeBytes)

	if err := model.DB.Where("email = ?", user.Email).First(&user).Error; err != nil {
		SendErrJSON("无效的邮箱", c)
		return
	}

	curTime := time.Now().Unix()
	activeUser := fmt.Sprintf("%s%d", model.ActiveTime, user.ID)

	RedisConn := model.RedisPool.Get()
	defer RedisConn.Close()

	if _, err := RedisConn.Do("SET", activeUser, curTime, "EX", activeDuration); err != nil {
		fmt.Println("redis set failed:", err)
	}
	go func() {
		sendMail("/active", "账号激活", curTime, user, c)
	}()

	c.JSON(http.StatusOK, gin.H{
		"errNo": model.ErrorCode.SUCCESS,
		"msg":   "success",
		"data": gin.H{
			"email": user.Email,
		},
	})
}

// ActiveAccount 激活账号
func ActiveAccount(c *gin.Context) {
	SendErrJSON := common.SendErrJSON
	var err error
	var user model.User
	if user, err = verifyLink(model.ActiveTime, c); err != nil {
		SendErrJSON("激活链接已失效", c)
		return
	}

	if user.ID <= 0 {
		SendErrJSON("激活链接已失效", c)
		return
	}

	updatedData := map[string]interface{}{
		"status":       model.UserStatusActived,
		"activated_at": time.Now(),
	}

	if err := model.DB.Model(&user).Updates(updatedData).Error; err != nil {
		SendErrJSON("error", c)
		return
	}

	RedisConn := model.RedisPool.Get()
	defer RedisConn.Close()

	if _, err := RedisConn.Do("DEL", fmt.Sprintf("%s%d", model.ActiveTime, user.ID)); err != nil {
		fmt.Println("redis delelte failed:", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"errNo": model.ErrorCode.SUCCESS,
		"msg":   "success",
		"data": gin.H{
			"email": user.Email,
		},
	})
}

// ResetPasswordMail 发送重置密码的邮件
func ResetPasswordMail(c *gin.Context) {
	SendErrJSON := common.SendErrJSON
	type UserReqData struct {
		Email       string `json:"email" binding:"required,email"`
		LuosimaoRes string `json:"luosimaoRes"`
	}
	var userData UserReqData
	if err := c.ShouldBindWith(&userData, binding.JSON); err != nil {
		SendErrJSON("无效的邮箱", c)
		return
	}

	verifyErr := utils.LuosimaoVerify(config.ServerConfig.LuosimaoVerifyURL, config.ServerConfig.LuosimaoAPIKey, userData.LuosimaoRes)

	if verifyErr != nil {
		SendErrJSON(verifyErr.Error(), c)
		return
	}

	var user model.User
	if err := model.DB.Where("email = ?", userData.Email).Find(&user).Error; err != nil {
		SendErrJSON("没有邮箱为 "+userData.Email+" 的用户", c)
		return
	}

	curTime := time.Now().Unix()
	resetUser := fmt.Sprintf("%s%d", model.ResetTime, user.ID)

	RedisConn := model.RedisPool.Get()
	defer RedisConn.Close()

	if _, err := RedisConn.Do("SET", resetUser, curTime, "EX", resetDuration); err != nil {
		fmt.Println("redis set failed:", err)
	}
	go func() {
		sendMail("/ac", "修改密码", curTime, user, c)
	}()

	c.JSON(http.StatusOK, gin.H{
		"errNo": model.ErrorCode.SUCCESS,
		"msg":   "success",
		"data":  gin.H{},
	})
}

// VerifyResetPasswordLink 验证重置密码的链接是否失效
func VerifyResetPasswordLink(c *gin.Context) {
	SendErrJSON := common.SendErrJSON
	if _, err := verifyLink(model.ResetTime, c); err != nil {
		fmt.Println(err.Error())
		SendErrJSON("重置链接已失效", c)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"errNo": model.ErrorCode.SUCCESS,
		"msg":   "success",
		"data":  gin.H{},
	})
}

// ResetPassword 重置密码
func ResetPassword(c *gin.Context) {
	SendErrJSON := common.SendErrJSON
	type UserReqData struct {
		Password string `json:"password" binding:"required,min=6,max=20"`
	}
	var userData UserReqData

	if err := c.ShouldBindWith(&userData, binding.JSON); err != nil {
		SendErrJSON("参数无效", c)
		return
	}

	var verifErr error
	var user model.User
	if user, verifErr = verifyLink(model.ResetTime, c); verifErr != nil {
		SendErrJSON("重置链接已失效", c)
		return
	}

	user.Pass = user.EncryptPassword(userData.Password, user.Salt())

	if user.ID <= 0 {
		SendErrJSON("重置链接已失效", c)
		return
	}
	if err := model.DB.Model(&user).Update("pass", user.Pass).Error; err != nil {
		SendErrJSON("error", c)
		return
	}

	RedisConn := model.RedisPool.Get()
	defer RedisConn.Close()

	if _, err := RedisConn.Do("DEL", fmt.Sprintf("%s%d", model.ResetTime, user.ID)); err != nil {
		fmt.Println("redis delelte failed:", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"errNo": model.ErrorCode.SUCCESS,
		"msg":   "success",
		"data":  gin.H{},
	})
}

// Signin 用户登录
func Signin(c *gin.Context) {
	fmt.Println("用户登录💕")
	SendErrJSON := common.SendErrJSON
	type EmailLogin struct {
		SigninInput string `json:"signinInput" binding:"required,email"`
		Password    string `json:"password" binding:"required,min=6,max=20"`
		LuosimaoRes string `json:"luosimaoRes"`
	}
	type UsernameLogin struct {
		SigninInput string `json:"signinInput" binding:"required,min=4,max=20"`
		Password    string `json:"password" binding:"required,min=6,max=20"`
		LuosimaoRes string `json:"luosimaoRes"`
	}
	var emailLogin EmailLogin
	var usernameLogin UsernameLogin
	var signinInput string
	var password string
	var luosimaoRes string
	var sql string

	if c.Query("loginType") == "email" {
		if err := c.ShouldBindWith(&emailLogin, binding.JSON); err != nil {
			fmt.Println(err.Error())
			SendErrJSON("邮箱或密码错误", c)
			return
		}
		signinInput = emailLogin.SigninInput
		password = emailLogin.Password
		luosimaoRes = emailLogin.LuosimaoRes
		sql = "email = ?"
	} else if c.Query("loginType") == "username" {
		if err := c.ShouldBindWith(&usernameLogin, binding.JSON); err != nil {
			fmt.Println(err.Error())
			SendErrJSON("用户名或密码错误", c)
			return
		}
		signinInput = usernameLogin.SigninInput
		password = usernameLogin.Password
		luosimaoRes = usernameLogin.LuosimaoRes
		sql = "name = ?"
	}
	fmt.Println("mafeng:", signinInput)
	fmt.Println("mafeng:", password)
	fmt.Println("luosi", luosimaoRes)
	verifyErr := utils.LuosimaoVerify(config.ServerConfig.LuosimaoVerifyURL, config.ServerConfig.LuosimaoAPIKey, luosimaoRes)

	if verifyErr != nil {
		fmt.Println("mafeng err")
		SendErrJSON(verifyErr.Error(), c)
		return
	}

	var user model.User
	if err := model.DB.Where(sql, signinInput).First(&user).Error; err != nil {
		SendErrJSON("账号不存在", c)
		return
	}

	if user.CheckPassword(password) {
		if user.Status == model.UserStatusInActive {
			encodedEmail := base64.StdEncoding.EncodeToString([]byte(user.Email))
			c.JSON(200, gin.H{
				"errNo": model.ErrorCode.InActive,
				"msg":   "账号未激活",
				"data": gin.H{
					"email": encodedEmail,
				},
			})
			return
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"id": user.ID,
		})
		tokenString, err := token.SignedString([]byte(config.ServerConfig.TokenSecret))
		if err != nil {
			fmt.Println(err.Error())
			SendErrJSON("内部错误", c)
			return
		}

		if err := model.UserToRedis(user); err != nil {
			SendErrJSON("内部错误.", c)
			return
		}
		fmt.Println("mafeng set token")
		c.SetCookie("token", tokenString, config.ServerConfig.TokenMaxAge, "/", "", false, true)
		fmt.Println("mafeng set cookie over")
		c.JSON(http.StatusOK, gin.H{
			"errNo": model.ErrorCode.SUCCESS,
			"msg":   "success",
			"data": gin.H{
				"token": tokenString,
				"user":  user,
			},
		})
		return
	}
	SendErrJSON("账号或密码错误", c)
}

// Signup 用户注册
func Signup(c *gin.Context) {
	SendErrJSON := common.SendErrJSON
	type UserReqData struct {
		Name     string `json:"name" binding:"required,min=4,max=20"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6,max=20"`
	}

	var userData UserReqData
	if err := c.ShouldBindWith(&userData, binding.JSON); err != nil {
		fmt.Println(err)
		SendErrJSON("参数无效", c)
		return
	}

	userData.Name = utils.AvoidXSS(userData.Name)
	userData.Name = strings.TrimSpace(userData.Name)
	userData.Email = strings.TrimSpace(userData.Email)

	if strings.Index(userData.Name, "@") != -1 {
		SendErrJSON("用户名中不能含有@字符", c)
		return
	}

	var user model.User
	if err := model.DB.Where("email = ? OR name = ?", userData.Email, userData.Name).Find(&user).Error; err == nil {
		if user.Name == userData.Name {
			SendErrJSON("用户名 "+user.Name+" 已被注册", c)
			return
		} else if user.Email == userData.Email {
			SendErrJSON("邮箱 "+user.Email+" 已存在", c)
			return
		}
	}

	var newUser model.User
	newUser.Name = userData.Name
	newUser.Email = userData.Email
	newUser.Pass = newUser.EncryptPassword(userData.Password, newUser.Salt())
	newUser.Role = model.UserRoleNormal
	newUser.Status = model.UserStatusInActive
	newUser.Sex = model.UserSexMale
	newUser.AvatarURL = "/images/avatar/" + strconv.Itoa(rand.Intn(2)) + ".png"

	if err := model.DB.Create(&newUser).Error; err != nil {
		SendErrJSON("error", c)
		return
	}

	curTime := time.Now().Unix()
	activeUser := fmt.Sprintf("%s%d", model.ActiveTime, newUser.ID)

	RedisConn := model.RedisPool.Get()
	defer RedisConn.Close()

	if _, err := RedisConn.Do("SET", activeUser, curTime, "EX", activeDuration); err != nil {
		fmt.Println("redis set failed:", err)
	}

	go func() {
		sendMail("/active", "账号激活", curTime, newUser, c)
	}()

	c.JSON(http.StatusOK, gin.H{
		"errNo": model.ErrorCode.SUCCESS,
		"msg":   "success",
		"data":  newUser,
	})
}

// Signout 退出登录
func Signout(c *gin.Context) {
	userInter, exists := c.Get("user")
	var user model.User
	if exists {
		user = userInter.(model.User)

		RedisConn := model.RedisPool.Get()
		defer RedisConn.Close()

		if _, err := RedisConn.Do("DEL", fmt.Sprintf("%s%d", model.LoginUser, user.ID)); err != nil {
			fmt.Println("redis delelte failed:", err)
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"errNo": model.ErrorCode.SUCCESS,
		"msg":   "success",
		"data":  gin.H{},
	})
}

// UpdateInfo 更新用户信息
func UpdateInfo(c *gin.Context) {
	SendErrJSON := common.SendErrJSON
	var userReqData model.User
	if err := c.ShouldBindWith(&userReqData, binding.JSON); err != nil {
		SendErrJSON("参数无效", c)
		return
	}
	userInter, _ := c.Get("user")
	user := userInter.(model.User)

	field := c.Param("field")
	resData := make(map[string]interface{})
	resData["id"] = user.ID

	switch field {
	case "sex":
		if userReqData.Sex != model.UserSexMale && userReqData.Sex != model.UserSexFemale {
			SendErrJSON("无效的性别", c)
			return
		}
		if err := model.DB.Model(&user).Update("sex", userReqData.Sex).Error; err != nil {
			fmt.Println(err.Error())
			SendErrJSON("error", c)
			return
		}
		resData[field] = userReqData.Sex
	case "signature":
		userReqData.Signature = utils.AvoidXSS(userReqData.Signature)
		userReqData.Signature = strings.TrimSpace(userReqData.Signature)
		// 个性签名可以为空
		if utf8.RuneCountInString(userReqData.Signature) > model.MaxSignatureLen {
			SendErrJSON("个性签名不能超过"+fmt.Sprintf("%d", model.MaxSignatureLen)+"个字符", c)
			return
		}
		if err := model.DB.Model(&user).Update("signature", userReqData.Signature).Error; err != nil {
			fmt.Println(err.Error())
			SendErrJSON("error", c)
			return
		}
		resData[field] = userReqData.Signature
	case "location":
		userReqData.Location = utils.AvoidXSS(userReqData.Location)
		userReqData.Location = strings.TrimSpace(userReqData.Location)
		// 居住地可以为空
		if utf8.RuneCountInString(userReqData.Location) > model.MaxLocationLen {
			SendErrJSON("居住地不能超过"+fmt.Sprintf("%d", model.MaxLocationLen)+"个字符", c)
			return
		}
		if err := model.DB.Model(&user).Update("location", userReqData.Location).Error; err != nil {
			fmt.Println(err.Error())
			SendErrJSON("error", c)
			return
		}
		resData[field] = userReqData.Location
	case "introduce":
		userReqData.Introduce = utils.AvoidXSS(userReqData.Introduce)
		userReqData.Introduce = strings.TrimSpace(userReqData.Introduce)
		// 个人简介可以为空
		if utf8.RuneCountInString(userReqData.Introduce) > model.MaxIntroduceLen {
			SendErrJSON("个人简介不能超过"+fmt.Sprintf("%d", model.MaxIntroduceLen)+"个字符", c)
			return
		}
		if err := model.DB.Model(&user).Update("introduce", userReqData.Introduce).Error; err != nil {
			fmt.Println(err.Error())
			SendErrJSON("error", c)
			return
		}
		resData[field] = userReqData.Introduce
	default:
		SendErrJSON("参数无效", c)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"errNo": model.ErrorCode.SUCCESS,
		"msg":   "success",
		"data":  resData,
	})
}

// UpdatePassword 更新用户密码
func UpdatePassword(c *gin.Context) {
	SendErrJSON := common.SendErrJSON
	type userReqData struct {
		Password string `json:"password" binding:"required,min=6,max=20"`
		NewPwd   string `json:"newPwd" binding:"required,min=6,max=20"`
	}
	var userData userReqData
	if err := c.ShouldBindWith(&userData, binding.JSON); err != nil {
		SendErrJSON("参数无效", c)
		return
	}

	userInter, _ := c.Get("user")
	user := userInter.(model.User)

	if err := model.DB.First(&user, user.ID).Error; err != nil {
		SendErrJSON("error", c)
		return
	}

	if user.CheckPassword(userData.Password) {
		user.Pass = user.EncryptPassword(userData.NewPwd, user.Salt())
		if err := model.DB.Save(&user).Error; err != nil {
			SendErrJSON("原密码不正确", c)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"errNo": model.ErrorCode.SUCCESS,
			"msg":   "success",
			"data":  gin.H{},
		})
	} else {
		SendErrJSON("原密码错误", c)
		return
	}
}

// PublicInfo 用户公开的信息
func PublicInfo(c *gin.Context) {
	SendErrJSON := common.SendErrJSON
	var userID int
	var idErr error

	if userID, idErr = strconv.Atoi(c.Param("id")); idErr != nil {
		fmt.Println(idErr.Error())
		SendErrJSON("无效的ID", c)
		return
	}
	var user model.User
	if err := model.DB.First(&user, userID).Error; err != nil {
		fmt.Println(err.Error())
		SendErrJSON("无效的ID", c)
		return
	}
	if user.Sex == model.UserSexFemale {
		user.CoverURL = "https://www.golang123.com/upload/img/2017/09/13/d20f62c6-bd11-4739-b79b-48c9fcbce392.jpg"
	} else {
		user.CoverURL = "https://www.golang123.com/upload/img/2017/09/13/e672995e-7a39-4a05-9673-8802b1865c46.jpg"
	}
	c.JSON(http.StatusOK, gin.H{
		"errNo": model.ErrorCode.SUCCESS,
		"msg":   "success",
		"data": gin.H{
			"user": user,
		},
	})
}

// SecretInfo 返回用户信息，包含一些私密字段
func SecretInfo(c *gin.Context) {
	if user, exists := c.Get("user"); exists {
		c.JSON(http.StatusOK, gin.H{
			"errNo": model.ErrorCode.SUCCESS,
			"msg":   "success",
			"data": gin.H{
				"user": user,
			},
		})
	}
}

// InfoDetail 返回用户详情信息(教育经历、职业经历等)，包含一些私密字段
func InfoDetail(c *gin.Context) {
	SendErrJSON := common.SendErrJSON
	userInter, _ := c.Get("user")
	user := userInter.(model.User)

	if err := model.DB.First(&user, user.ID).Error; err != nil {
		SendErrJSON("error", c)
		return
	}

	if err := model.DB.Model(&user).Related(&user.Schools).Error; err != nil {
		SendErrJSON("error", c)
		return
	}

	if err := model.DB.Model(&user).Related(&user.Careers).Error; err != nil {
		SendErrJSON("error", c)
		return
	}

	if user.Sex == model.UserSexFemale {
		user.CoverURL = "https://www.golang123.com/upload/img/2017/09/13/d20f62c6-bd11-4739-b79b-48c9fcbce392.jpg"
	} else {
		user.CoverURL = "https://www.golang123.com/upload/img/2017/09/13/e672995e-7a39-4a05-9673-8802b1865c46.jpg"
	}

	c.JSON(http.StatusOK, gin.H{
		"errNo": model.ErrorCode.SUCCESS,
		"msg":   "success",
		"data": gin.H{
			"user": user,
		},
	})
}

// AllList 查询用户列表，只有管理员才能调此接口
func AllList(c *gin.Context) {
	SendErrJSON := common.SendErrJSON
	role, _ := strconv.Atoi(c.Query("role"))
	allUserRole := []int{
		model.UserRoleNormal,
		model.UserRoleEditor,
		model.UserRoleAdmin,
		model.UserRoleCrawler,
		model.UserRoleSuperAdmin,
	}
	foundRole := false
	for _, r := range allUserRole {
		if r == role {
			foundRole = true
			break
		}
	}

	var startTime string
	var endTime string

	if startAt, err := strconv.Atoi(c.Query("startAt")); err != nil {
		startTime = time.Unix(0, 0).Format("2006-01-02 15:04:05")
	} else {
		startTime = time.Unix(int64(startAt/1000), 0).Format("2006-01-02 15:04:05")
	}

	if endAt, err := strconv.Atoi(c.Query("endAt")); err != nil {
		endTime = time.Now().Format("2006-01-02 15:04:05")
	} else {
		endTime = time.Unix(int64(endAt/1000), 0).Format("2006-01-02 15:04:05")
	}

	pageNo, pageNoErr := strconv.Atoi(c.Query("pageNo"))
	if pageNoErr != nil {
		pageNo = 1
	}
	if pageNo < 1 {
		pageNo = 1
	}

	offset := (pageNo - 1) * model.PageSize
	pageSize := model.PageSize

	var users []model.User
	var totalCount int
	if foundRole {
		if err := model.DB.Model(&model.User{}).Where("created_at >= ? AND created_at < ? AND role = ?", startTime, endTime, role).
			Count(&totalCount).Error; err != nil {
			fmt.Println(err.Error())
			SendErrJSON("error", c)
			return
		}
		if err := model.DB.Where("created_at >= ? AND created_at < ? AND role = ?", startTime, endTime, role).
			Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&users).Error; err != nil {
			fmt.Println(err.Error())
			SendErrJSON("error", c)
			return
		}
	} else {
		if err := model.DB.Model(&model.User{}).Where("created_at >= ? AND created_at < ?", startTime, endTime).
			Count(&totalCount).Error; err != nil {
			fmt.Println(err.Error())
			SendErrJSON("error", c)
			return
		}
		if err := model.DB.Where("created_at >= ? AND created_at < ?", startTime, endTime).Order("created_at DESC").Offset(offset).
			Limit(pageSize).Find(&users).Error; err != nil {
			fmt.Println(err.Error())
			SendErrJSON("error", c)
			return
		}
	}
	var results []interface{}
	for i := 0; i < len(users); i++ {
		results = append(results, gin.H{
			"id":          users[i].ID,
			"name":        users[i].Name,
			"email":       users[i].Email,
			"role":        users[i].Role,
			"status":      users[i].Status,
			"createdAt":   users[i].CreatedAt,
			"activatedAt": users[i].ActivatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"errNo": model.ErrorCode.SUCCESS,
		"msg":   "success",
		"data": gin.H{
			"users":      results,
			"pageNo":     pageNo,
			"pageSize":   pageSize,
			"totalCount": totalCount,
		},
	})
}

func topN(c *gin.Context, n int) {
	SendErrJSON := common.SendErrJSON
	var users []model.User
	if err := model.DB.Order("score DESC").Limit(n).Find(&users).Error; err != nil {
		fmt.Println(err.Error())
		SendErrJSON("error", c)
	} else {
		c.JSON(http.StatusOK, gin.H{
			"errNo": model.ErrorCode.SUCCESS,
			"msg":   "success",
			"data": gin.H{
				"users": users,
			},
		})
	}
}

// Top10 返回积分排名前10的用户
func Top10(c *gin.Context) {
	topN(c, 10)
}

// Top100 返回积分排名前100的用户
func Top100(c *gin.Context) {
	topN(c, 100)
}

// UploadAvatar 上传用户头像
func UploadAvatar(c *gin.Context) {
	SendErrJSON := common.SendErrJSON
	data, err := common.Upload(c)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"errNo": model.ErrorCode.ERROR,
			"msg":   err.Error(),
			"data":  gin.H{},
		})
		return
	}

	avatarURL := data["url"].(string)
	userInter, _ := c.Get("user")
	user := userInter.(model.User)

	if err := model.DB.Model(&user).Update("avatar_url", avatarURL).Error; err != nil {
		c.JSON(http.StatusOK, gin.H{
			"errNo": model.ErrorCode.ERROR,
			"msg":   err.Error(),
			"data":  gin.H{},
		})
		return
	}
	user.AvatarURL = avatarURL

	if model.UserToRedis(user) != nil {
		SendErrJSON("error", c)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"errNo": model.ErrorCode.SUCCESS,
		"msg":   "success",
		"data":  data,
	})
}

// AddCareer 添加职业经历
func AddCareer(c *gin.Context) {
	SendErrJSON := common.SendErrJSON
	var career model.Career
	if err := c.ShouldBindWith(&career, binding.JSON); err != nil {
		SendErrJSON("参数无效", c)
		return
	}

	career.Company = utils.AvoidXSS(career.Company)
	career.Company = strings.TrimSpace(career.Company)
	career.Title = utils.AvoidXSS(career.Title)
	career.Title = strings.TrimSpace(career.Title)

	if career.Company == "" {
		SendErrJSON("公司或组织名称不能为空", c)
		return
	}

	if utf8.RuneCountInString(career.Company) > model.MaxCareerCompanyLen {
		SendErrJSON("公司或组织名称不能超过"+fmt.Sprintf("%d", model.MaxCareerCompanyLen)+"个字符", c)
		return
	}

	if career.Title == "" {
		SendErrJSON("职位不能为空", c)
		return
	}

	if utf8.RuneCountInString(career.Title) > model.MaxCareerTitleLen {
		SendErrJSON("职位不能超过"+fmt.Sprintf("%d", model.MaxCareerTitleLen)+"个字符", c)
		return
	}

	userInter, _ := c.Get("user")
	user := userInter.(model.User)
	career.UserID = user.ID

	if err := model.DB.Create(&career).Error; err != nil {
		SendErrJSON("error", c)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"errNo": model.ErrorCode.SUCCESS,
		"msg":   "success",
		"data":  career,
	})
}

// AddSchool 添加教育经历
func AddSchool(c *gin.Context) {
	SendErrJSON := common.SendErrJSON
	var school model.School
	if err := c.ShouldBindWith(&school, binding.JSON); err != nil {
		SendErrJSON("参数无效", c)
		return
	}

	school.Name = utils.AvoidXSS(school.Name)
	school.Name = strings.TrimSpace(school.Name)
	school.Speciality = utils.AvoidXSS(school.Speciality)
	school.Speciality = strings.TrimSpace(school.Speciality)

	if school.Name == "" {
		SendErrJSON("学校或教育机构名不能为空", c)
		return
	}

	if utf8.RuneCountInString(school.Name) > model.MaxSchoolNameLen {
		SendErrJSON("学校或教育机构名不能超过"+fmt.Sprintf("%d", model.MaxSchoolNameLen)+"个字符", c)
		return
	}

	if school.Speciality == "" {
		SendErrJSON("专业方向不能为空", c)
		return
	}

	if utf8.RuneCountInString(school.Speciality) > model.MaxSchoolSpecialityLen {
		SendErrJSON("专业方向不能超过"+fmt.Sprintf("%d", model.MaxSchoolSpecialityLen)+"个字符", c)
		return
	}

	userInter, _ := c.Get("user")
	user := userInter.(model.User)
	school.UserID = user.ID

	if err := model.DB.Create(&school).Error; err != nil {
		SendErrJSON("error", c)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"errNo": model.ErrorCode.SUCCESS,
		"msg":   "success",
		"data":  school,
	})
}

// DeleteCareer 删除职业经历
func DeleteCareer(c *gin.Context) {
	SendErrJSON := common.SendErrJSON
	var id int
	var idErr error
	if id, idErr = strconv.Atoi(c.Param("id")); idErr != nil {
		SendErrJSON("无效的id", c)
		return
	}
	var career model.Career
	if err := model.DB.First(&career, id).Error; err != nil {
		SendErrJSON("无效的id.", c)
		return
	}

	if err := model.DB.Delete(&career).Error; err != nil {
		SendErrJSON("error", c)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"errNo": model.ErrorCode.SUCCESS,
		"msg":   "success",
		"data": gin.H{
			"id": career.ID,
		},
	})
}

// DeleteSchool 删除教育经历
func DeleteSchool(c *gin.Context) {
	SendErrJSON := common.SendErrJSON
	var id int
	var idErr error
	if id, idErr = strconv.Atoi(c.Param("id")); idErr != nil {
		SendErrJSON("无效的id", c)
		return
	}
	var school model.School
	if err := model.DB.First(&school, id).Error; err != nil {
		SendErrJSON("无效的id.", c)
		return
	}

	if err := model.DB.Delete(&school).Error; err != nil {
		SendErrJSON("error", c)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"errNo": model.ErrorCode.SUCCESS,
		"msg":   "success",
		"data": gin.H{
			"id": school.ID,
		},
	})
}
