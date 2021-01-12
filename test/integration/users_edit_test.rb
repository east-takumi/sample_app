require 'test_helper'

class UsersEditTest < ActionDispatch::IntegrationTest
  def setup
    @user = users(:michael)
  end

  test "unsuccessful edit" do
    log_in_as(@user) 
    get edit_user_path(@user)                                                   # userIDを取得(michael)
    assert_template 'users/edit'                                                # editビューが描画できてたらtrue
    patch user_path(@user), params: { user: { name: "",                         # 引数としてわざと失敗する値を持ったuserIDをpatchリクエストで送信（更新）する
                                              email: "foo@invalid",
                                              password:              "foo",
                                              password_confirmation: "bar" } }
    assert_template 'users/edit'                                                # editビューが描画できてたらtrue
  end
  
  test "successful edit" do
    log_in_as(@user) 
    get edit_user_path(@user)                                                   # userIDを取得(michael)
    assert_template 'users/edit'                                                # editビューが描画できてたらtrue
    name  = "Foo Bar"                                                           # フォーム欄に値を入力する
    email = "foo@bar.com"                                                       
    patch user_path(@user), params: { user: { name: name,                       # 引数としてわざと失敗する値を持ったuserIDをpatchリクエストで送信（更新）する
                                              email: email,
                                              password:              "",
                                              password_confirmation: "" } }
    assert_not flash.empty?                                                     # エラー文が空じゃなければtrue
    assert_redirected_to @user                                                  # michaelのユーザーidページへ移動できたらtrue
    @user.reload
    assert_equal name,  @user.name                                              # DB内の名前と@userの名前が一致していていたらtrue
    assert_equal email, @user.email                                             # DB内のEmailと@userの名前が一致
  end
end
